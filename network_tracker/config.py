import configparser
import os
import pathlib

_DEFAULT_CONFIG = pathlib.Path(__file__).parent.parent / "config.ini"


def load(path: str | None = None) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(str(path or _DEFAULT_CONFIG))

    # Env vars override config file values (useful for Docker secrets)
    if tok := os.environ.get("TELEGRAM_BOT_TOKEN"):
        cfg.setdefault("telegram", {})
        cfg["telegram"]["bot_token"] = tok
    if cid := os.environ.get("TELEGRAM_CHAT_ID"):
        cfg.setdefault("telegram", {})
        cfg["telegram"]["chat_id"] = cid

    return cfg
