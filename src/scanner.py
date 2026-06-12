"""Обёртка над утилитой Masscan: запуск сканирования и парсинг JSON-вывода."""

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

MAC_RE = re.compile(r"lladdr ([0-9a-fA-F:]{17})")


class MasscanError(Exception):
    """Ошибка запуска или работы Masscan."""


def is_ip_range(target):
    """Проверяет запись диапазона Masscan вида '10.0.0.1-10.0.0.20'."""
    if target.count("-") != 1:
        return False
    start, end = target.split("-")
    try:
        ipaddress.ip_address(start.strip())
        ipaddress.ip_address(end.strip())
        return True
    except ValueError:
        return False


def is_single_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def route_info(ip):
    """Возвращает {'local': bool, 'iface': str} по выводу `ip route get`.
    Локальной считается цель в той же подсети (в маршруте нет 'via')."""
    try:
        proc = subprocess.run(
            ["ip", "route", "get", ip],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    parts = proc.stdout.split()
    iface = parts[parts.index("dev") + 1] if "dev" in parts else None
    return {"local": " via " not in proc.stdout, "iface": iface}


def read_neigh(ip, iface):
    cmd = ["ip", "neigh", "show", ip]
    if iface:
        cmd += ["dev", iface]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    match = MAC_RE.search(proc.stdout)
    return match.group(1) if match else None


def resolve_mac(ip, iface):
    """Узнаёт MAC локальной цели через ARP-кэш ОС, при необходимости провоцируя
    ARP коротким TCP-подключением (SYN отправляется только после ARP, поэтому
    результат не зависит от того, открыт ли порт)."""
    mac = read_neigh(ip, iface)
    if mac:
        return mac
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((ip, 80))
        except OSError:
            pass
        finally:
            sock.close()
    except OSError:
        pass
    return read_neigh(ip, iface)


def parse_output(output_path):
    text = output_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # Masscan иногда оставляет висящую запятую перед закрывающей скобкой,
    # из-за чего стандартный json.loads падает — убираем её перед разбором.
    try:
        records = json.loads(text)
    except json.JSONDecodeError:
        records = json.loads(re.sub(r",\s*]$", "]", text))

    results = []
    for rec in records:
        ip = rec.get("ip")
        for port_info in rec.get("ports", []):
            if port_info.get("status") != "open":
                continue
            results.append(
                OpenPort(ip, port_info["port"], port_info.get("proto", "tcp"))
            )
    return results


def resolve_targets(targets):
    """Masscan не умеет резолвить DNS — приводим доменные имена к IP,
    а IP-адреса, CIDR-подсети и диапазоны вида a.b.c.d-e.f.g.h
    передаём без изменений."""
    resolved = []
    for raw in targets:
        target = raw.strip()
        if not target:
            continue
        if "/" in target or is_ip_range(target) or is_single_ip(target):
            resolved.append(target)
            continue
        try:
            resolved.append(socket.gethostbyname(target))
        except socket.gaierror as exc:
            raise MasscanError(f"Не удалось разрешить имя '{target}': {exc}") from exc
    if not resolved:
        raise MasscanError("После обработки целей не осталось ни одного адреса.")
    return resolved


class OpenPort:
    """Один открытый порт, обнаруженный Masscan."""

    def __init__(self, ip, port, proto):
        self.ip = ip
        self.port = int(port)
        self.proto = proto

    def __repr__(self):
        return f"OpenPort({self.ip}:{self.port}/{self.proto})"


class MasscanScanner:
    """Запускает Masscan и возвращает список обнаруженных открытых портов.

    Masscan самостоятельно ведёт асинхронное многопоточное сканирование,
    поэтому потоки здесь не создаются — параллелизм обеспечивает сам сканер,
    а скорость регулируется параметром rate.
    """

    def __init__(self, config):
        self.config = config

    def is_available(self):
        return shutil.which(self.config.path) is not None

    def build_command(self, targets, ports, output_path, router_mac=None):
        cmd = []
        if self.config.use_sudo:
            cmd.append("sudo")
        cmd += [
            self.config.path,
            "-p", ports,
            "--rate", str(self.config.rate),
            "-oJ", str(output_path),
            "--wait", str(self.config.wait),
        ]
        if router_mac:
            cmd += ["--router-mac", router_mac]
        cmd += list(self.config.extra_args)
        cmd += list(targets)
        return cmd

    def scan(self, targets, ports):
        if not self.is_available():
            raise MasscanError(
                f"Masscan не найден (искали '{self.config.path}'). "
                f"Установите его: sudo apt install masscan."
            )

        targets = resolve_targets(targets)

        # Цели в локальной подсети Masscan должен адресовать на L2 по MAC самого
        # хоста, но в части окружений (например, VMware) его ARP не срабатывает,
        # и пакеты не уходят. Поэтому MAC локальных целей резолвим через ARP-стек
        # ОС и передаём явным --router-mac, а цели группируем по этому MAC, так
        # как Masscan принимает только один --router-mac на запуск. Цели за
        # шлюзом и подсети/диапазоны сканируются обычным образом (router_mac=None).
        groups = self.group_by_nexthop(targets)
        results = []
        errors = []
        for router_mac, group in groups.items():
            try:
                results.extend(self.run_masscan(group, ports, router_mac))
            except MasscanError as exc:
                errors.append(str(exc))
        if errors and not results:
            raise MasscanError("; ".join(errors))
        return results

    def run_masscan(self, targets, ports, router_mac):
        with tempfile.NamedTemporaryFile(
            prefix="masscan-", suffix=".json", delete=False
        ) as tmp:
            output_path = Path(tmp.name)

        cmd = self.build_command(targets, ports, output_path, router_mac)
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if proc.returncode != 0:
                raise MasscanError(
                    f"Masscan завершился с кодом {proc.returncode}: "
                    f"{proc.stderr.strip()}"
                )
            return parse_output(output_path)
        finally:
            output_path.unlink(missing_ok=True)

    def group_by_nexthop(self, targets):
        groups = defaultdict(list)
        for target in targets:
            router_mac = None
            if is_single_ip(target):
                info = route_info(target)
                if info and info["local"] and info["iface"] != "lo":
                    router_mac = resolve_mac(target, info["iface"])
            groups[router_mac].append(target)
        return groups
