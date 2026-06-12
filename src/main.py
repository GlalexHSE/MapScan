"""Точка входа: связывает сканер, анализ баннеров, хранилище, уведомления,
планировщик и дашборд. Поддерживает разовый скан и режим сервера."""

import argparse
import sys
import threading

from .banner import BannerGrabber
from .config import Config, ConfigError
from .dashboard import Dashboard
from .notifier import TelegramNotifier
from .scanner import MasscanError, MasscanScanner, resolve_targets
from .scheduler import ScanScheduler
from .storage import Storage


class ScannerApp:
    def __init__(self, config):
        self.config = config
        self.storage = Storage(config.db_path)
        self.scanner = MasscanScanner(config.masscan)
        self.grabber = BannerGrabber(config.banner_grab)
        self.notifier = TelegramNotifier(config.telegram)
        self.scan_lock = threading.Lock()

    def run_scan(self, targets=None, ports=None):
        """Полный цикл: скан → баннеры → сохранение → уведомление.

        Без аргументов сканирует цели и порты из конфигурации; targets/ports
        позволяют переопределить их для разового скана. Сериализацию запусков
        обеспечивает scan_serialized / общий scan_lock, чтобы Masscan не
        запускался в нескольких экземплярах одновременно.
        """
        targets = targets or self.config.targets
        ports = ports or self.config.ports
        print(f"[scan] Запуск Masscan по целям: {', '.join(targets)}")
        open_ports = self.scanner.scan(targets, ports)
        print(f"[scan] Открытых портов найдено: {len(open_ports)}")

        results = self.grabber.grab_all(open_ports)
        scan_id, new_findings = self.storage.record_scan(targets, results)
        print(f"[scan] Скан #{scan_id}: новых сервисов — {len(new_findings)}")

        if new_findings:
            sent = self.notifier.notify_new_findings(new_findings, scan_id)
            if sent:
                print(f"[scan] Уведомление о {len(new_findings)} находках отправлено.")
        return scan_id, results, new_findings

    def scan_serialized(self, targets=None, ports=None):
        """Блокирующий запуск скана для планировщика: дожидается, пока
        освободится общий лок, и только потом сканирует."""
        with self.scan_lock:
            return self.run_scan(targets, ports)

    def serve(self):
        dashboard = Dashboard(
            self.config.dashboard, self.storage, self.run_scan, self.scan_lock
        )
        scheduler = None
        if self.config.scheduler.enabled:
            scheduler = ScanScheduler(
                self.scan_serialized,
                self.config.scheduler.interval_minutes,
                self.config.scheduler.run_on_start,
            )
            scheduler.start()
            print(
                f"[serve] Планировщик включён: интервал "
                f"{self.config.scheduler.interval_minutes} мин."
            )

        print(f"[serve] Дашборд доступен на {dashboard.url}")
        try:
            dashboard.serve_forever()
        except KeyboardInterrupt:
            print("\n[serve] Остановка...")
        finally:
            if scheduler:
                scheduler.stop()
            dashboard.shutdown()


def load_config(path):
    try:
        return Config.from_file(path)
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        sys.exit(2)


def print_report(targets, results):
    """Печатает результаты скана по хостам в табличном виде, как nmap."""
    by_host = {}
    for res in results:
        by_host.setdefault(res.ip, []).append(res)

    print(f"\nОтчёт о сканировании ({len(targets)} целей, "
          f"открытых портов: {len(results)})")
    for ip in sorted(by_host):
        ports = sorted(by_host[ip], key=lambda r: r.port)
        print(f"\nХост: {ip} — открытых портов: {len(ports)}")
        print(f"  {'PORT':<11}{'STATE':<7}{'SERVICE':<15}BANNER")
        for r in ports:
            banner = r.banner.replace("\n", " ").replace("\r", " ").strip()
            if len(banner) > 60:
                banner = banner[:57] + "..."
            print(f"  {f'{r.port}/{r.proto}':<11}{'open':<7}{r.service:<15}{banner}")

    silent = [t for t in targets if t not in by_host]
    if silent:
        print(f"\nБез открытых портов / без ответа: {', '.join(silent)}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Сетевой сканер на базе Masscan с дашбордом и уведомлениями.",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Путь к файлу конфигурации (по умолчанию: config.json).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan", help="Выполнить одно сканирование и выйти.")
    sub.add_parser("serve", help="Запустить дашборд и планировщик.")

    args = parser.parse_args(argv)
    config = load_config(args.config)

    app = ScannerApp(config)
    try:
        if args.command == "scan":
            _, results, _ = app.run_scan()
            print_report(resolve_targets(config.targets), results)
        elif args.command == "serve":
            app.serve()
    except MasscanError as exc:
        print(f"Ошибка Masscan: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
