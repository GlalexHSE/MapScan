"""Загрузка и валидация конфигурации из JSON-файла."""

import json
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    """Ошибка в структуре или значениях конфигурационного файла."""


@dataclass
class MasscanConfig:
    path: str = "masscan"
    rate: int = 1000
    use_sudo: bool = True
    wait: int = 5
    extra_args: list = field(default_factory=list)


@dataclass
class BannerConfig:
    enabled: bool = True
    timeout: float = 4.0
    max_bytes: int = 512
    max_workers: int = 50


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class SchedulerConfig:
    enabled: bool = True
    interval_minutes: int = 60
    run_on_start: bool = True


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8800


@dataclass
class Config:
    targets: list
    ports: str
    db_path: str
    masscan: MasscanConfig
    banner_grab: BannerConfig
    telegram: TelegramConfig
    scheduler: SchedulerConfig
    dashboard: DashboardConfig

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            raise ConfigError(
                f"Файл конфигурации не найден: {path}. "
                f"Скопируйте config.example.json в config.json."
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Невалидный JSON в {path}: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw):
        targets = raw.get("targets") or []
        if not isinstance(targets, list) or not targets:
            raise ConfigError("Поле 'targets' должно быть непустым списком.")

        ports = raw.get("ports")
        if not isinstance(ports, str) or not ports.strip():
            raise ConfigError("Поле 'ports' должно быть непустой строкой, например '1-1024,8080'.")

        storage = raw.get("storage") or {}
        db_path = storage.get("db_path", "data/scanner.db")

        return cls(
            targets=targets,
            ports=ports,
            db_path=db_path,
            masscan=MasscanConfig(**(raw.get("masscan") or {})),
            banner_grab=BannerConfig(**(raw.get("banner_grab") or {})),
            telegram=TelegramConfig(**(raw.get("telegram") or {})),
            scheduler=SchedulerConfig(**(raw.get("scheduler") or {})),
            dashboard=DashboardConfig(**(raw.get("dashboard") or {})),
        )
