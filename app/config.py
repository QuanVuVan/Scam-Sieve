"""
Doc cau hinh tu file .env.
Khong dung pydantic-settings de giu don gian, de hieu cho sinh vien.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # doc file .env o thu muc goc du an


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scamsieve.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-secret-key-in-production")
    SESSION_COOKIE_NAME: str = "scamsieve_session"
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"


settings = Settings()
