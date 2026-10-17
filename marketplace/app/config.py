from __future__ import annotations
import os
from dataclasses import dataclass
from dotenv import load_dotenv
load_dotenv()


def boolean(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"true", "1", "yes", "on"}

@dataclass(frozen=True)
class Config:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/ganj_marketplace.db")
    session_secret: str = os.getenv("SESSION_SECRET", "")
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    webhook_secret: str = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    telegram_bot_username: str = os.getenv("TELEGRAM_BOT_USERNAME", "")
    owner_id: int = int(os.getenv("OWNER_TELEGRAM_ID", "907322593"))
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")
    cookie_secure: bool = boolean("COOKIE_SECURE", True)
    dry_run: bool = boolean("DRY_RUN", True)
    host_ops_enabled: bool = boolean("ENABLE_HOST_OPERATIONS", False)
    fernet_key: str = os.getenv("FERNET_KEY", "")

config = Config()
