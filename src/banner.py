"""Захват баннеров с открытых портов и определение сервиса по сигнатурам."""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

WELL_KNOWN_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Сигнатуры в порядке проверки: первое совпадение определяет сервис.
BANNER_SIGNATURES = [
    ("ssh", re.compile(rb"^SSH-")),
    ("http", re.compile(rb"^HTTP/")),
    ("ftp", re.compile(rb"^220.*\b(ftp|filezilla|vsftpd|pure-ftpd)\b", re.IGNORECASE)),
    ("smtp", re.compile(rb"^220.*\b(smtp|esmtp|postfix|exim|sendmail)\b", re.IGNORECASE)),
    ("imap", re.compile(rb"^\* OK.*IMAP", re.IGNORECASE)),
    ("pop3", re.compile(rb"^\+OK")),
    ("mysql", re.compile(rb"mysql", re.IGNORECASE)),
    ("redis", re.compile(rb"^-ERR|^\+PONG|redis", re.IGNORECASE)),
    ("rdp", re.compile(rb"^\x03\x00\x00")),
    ("vnc", re.compile(rb"^RFB ")),
    ("mongodb", re.compile(rb"mongodb", re.IGNORECASE)),
]

# Для портов, которые молчат до запроса, отправляем безобидный пробник.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"
HTTP_PORTS = {80, 8080, 8000, 8888, 443, 8443}


def service_by_port(port):
    return WELL_KNOWN_PORTS.get(port, "unknown")


def identify_service(port, banner):
    for service, pattern in BANNER_SIGNATURES:
        if pattern.search(banner):
            return service
    return service_by_port(port)


class BannerResult:
    def __init__(self, ip, port, proto, service, banner):
        self.ip = ip
        self.port = port
        self.proto = proto
        self.service = service
        self.banner = banner

    def as_dict(self):
        return {
            "ip": self.ip,
            "port": self.port,
            "proto": self.proto,
            "service": self.service,
            "banner": self.banner,
        }


class BannerGrabber:
    """Параллельно опрашивает открытые порты и определяет сервисы.

    Multithreading здесь оправдан: захват баннера — это операция с долгим
    ожиданием сети (I/O bound), поэтому десятки сокетов открываются
    одновременно через пул потоков.
    """

    def __init__(self, config):
        self.timeout = config.timeout
        self.max_bytes = config.max_bytes
        self.max_workers = config.max_workers
        self.enabled = config.enabled

    def grab_all(self, open_ports):
        if not self.enabled:
            return [
                BannerResult(p.ip, p.port, p.proto, service_by_port(p.port), "")
                for p in open_ports
            ]

        results = []
        workers = min(self.max_workers, max(1, len(open_ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.grab_one, p): p for p in open_ports}
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def grab_one(self, open_port):
        banner = self.read_banner(open_port.ip, open_port.port)
        service = identify_service(open_port.port, banner)
        text = banner.decode("latin-1", errors="replace").strip() if banner else ""
        return BannerResult(open_port.ip, open_port.port, open_port.proto, service, text)

    def read_banner(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                if port in HTTP_PORTS:
                    sock.sendall(HTTP_PROBE)
                return sock.recv(self.max_bytes)
        except (OSError, socket.timeout):
            return b""
