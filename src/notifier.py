"""Уведомления о новых сервисах через Telegram Bot API (только stdlib)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.telegram.org/bot{token}/sendMessage"
MAX_MESSAGE_LEN = 4096
MAX_MESSAGES = 5


def is_significant(finding):
    """Находка значима, если сервис распознан или есть баннер. Отсекает шум
    вида unknown с пустым баннером (например, от SYN-proxy, который отвечает
    «открыто» на сотни портов без реальных сервисов за ними)."""
    return finding.service != "unknown" or bool(finding.banner.strip())


def format_block(finding):
    banner = finding.banner.replace("\n", " ").strip()
    if len(banner) > 80:
        banner = banner[:77] + "..."
    block = f"▸ {finding.ip}:{finding.port}/{finding.proto} — {finding.service}"
    if banner:
        block += f"\n   {banner}"
    return block


def build_messages(findings, scan_id):
    """Разбивает находки на несколько сообщений, чтобы каждое влезало в лимит
    Telegram (4096 символов). При очень большом числе находок ограничивает
    число сообщений и добавляет пометку об остатке, чтобы не спамить чат."""
    total = len(findings)
    messages = []
    current = f"\U0001F6A8 Новых открытых сервисов: {total} (скан #{scan_id})"
    for idx, finding in enumerate(findings):
        block = format_block(finding)
        if len(current) + len(block) + 1 > MAX_MESSAGE_LEN:
            messages.append(current)
            current = ""
            if len(messages) >= MAX_MESSAGES:
                note = f"\n… и ещё {total - idx}, полный список на дашборде."
                last = messages[-1]
                if len(last) + len(note) > MAX_MESSAGE_LEN:
                    last = last[:MAX_MESSAGE_LEN - len(note)].rsplit("\n", 1)[0]
                messages[-1] = last + note
                return messages
        current += ("\n" if current else "") + block
    if current:
        messages.append(current)
    return messages


class TelegramNotifier:
    def __init__(self, config):
        self.enabled = config.enabled
        self.bot_token = config.bot_token
        self.chat_id = config.chat_id

    def notify_new_findings(self, findings, scan_id):
        if not self.enabled:
            return False
        significant = [f for f in findings if is_significant(f)]
        if not significant:
            return False
        ok = True
        messages = build_messages(significant, scan_id)
        for i, text in enumerate(messages):
            if not self.send(text):
                ok = False
            if i < len(messages) - 1:
                time.sleep(0.4)  # не упереться в rate limit Telegram
        return ok

    def send(self, text):
        url = API_URL.format(token=self.bot_token)
        payload = urllib.parse.urlencode(
            {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": "true"}
        ).encode("utf-8")
        request = urllib.request.Request(url, data=payload, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return bool(body.get("ok"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            print(f"[notifier] Не удалось отправить уведомление в Telegram: {exc}")
            return False
