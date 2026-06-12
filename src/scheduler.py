"""Периодический запуск задачи в фоновом потоке."""

import threading


class ScanScheduler:
    """Вызывает переданную функцию с фиксированным интервалом в фоне.

    Интервал отсчитывается между завершением одного запуска и началом
    следующего ожидания, поэтому долгий скан не накладывается сам на себя.
    Остановка реализована через Event, чтобы не ждать весь интервал при
    выключении.
    """

    def __init__(self, job, interval_minutes, run_on_start=True):
        self.job = job
        self.interval_seconds = max(1, int(interval_minutes * 60))
        self.run_on_start = run_on_start
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self.loop, name="scan-scheduler", daemon=True)
        self.thread.start()

    def loop(self):
        if self.run_on_start:
            self.run_job()
        while not self.stop_event.wait(self.interval_seconds):
            self.run_job()

    def run_job(self):
        try:
            self.job()
        except Exception as exc:  # фоновый поток не должен падать молча
            print(f"[scheduler] Запланированный скан завершился ошибкой: {exc}")

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
