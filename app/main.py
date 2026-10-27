"""
Diem khoi dau cua ung dung ScamSieve.
Chay bang: uvicorn app.main:app --reload
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.routers import pages, scan, reports, api_v1, chat

# Import cac model de SQLAlchemy Base.metadata "biet" ve tat ca cac bang truoc khi create_all()
from app.models import user, blacklist, report, scan as scan_model  # noqa: F401

logger = logging.getLogger(__name__)

# Tao bang trong DB neu chua ton tai.
Base.metadata.create_all(bind=engine)


async def periodic_threat_sync():
    """
    Tiến trình chạy ngầm (Background Worker) tự động cập nhật tình báo đe dọa:
    Định kỳ mỗi 6 giờ tự động kéo các tên miền phishing mới từ URLhaus và OpenPhish
    vào SQLite Blacklist và nạp tức thời vào bộ nhớ đệm RAM O(1).
    """
    from app.database import SessionLocal
    from app.services.threat_feed_service import threat_feed_service

    # Chờ 20 giây sau khi máy chủ khởi động hoàn tất trước khi chạy lần đầu
    await asyncio.sleep(20)
    while True:
        try:
            logger.info("Bắt đầu tự động cập nhật danh sách đen từ OpenPhish & URLhaus...")
            db = SessionLocal()
            try:
                res = threat_feed_service.sync_all_feeds(db, limit_per_feed=250)
                logger.info(f"Hoàn tất cập nhật: +{res.get('new_db_domains_inserted')} tên miền mới vào Blacklist.")
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Lỗi trong tiến trình đồng bộ Threat Intel định kỳ: {e}")

        # Chu kỳ lặp lại: 6 giờ (21.600 giây)
        await asyncio.sleep(21600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Quản lý vòng đời ứng dụng FastAPI (Lifespan Context Manager):
    1. Tự động nạp toàn bộ danh sách đen tên miền từ SQLite vào bộ nhớ đệm RAM O(1) khi máy chủ khởi động.
    2. Kích hoạt tiến trình chạy ngầm tự động đồng bộ đe dọa định kỳ.
    """
    from app.database import SessionLocal
    from app.services.blacklist_service import threat_intel
    db = SessionLocal()
    try:
        threat_intel.load_from_database(db)
    finally:
        db.close()

    # Kích hoạt worker ngầm tự động cập nhật danh sách đen (bỏ qua khi đang chạy test)
    import sys
    import os
    is_testing = "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ
    sync_task = None
    if not is_testing:
        sync_task = asyncio.create_task(periodic_threat_sync())
    yield
    # Hủy tác vụ ngầm khi tắt server
    if sync_task:
        sync_task.cancel()
        try:
            await sync_task
        except (asyncio.CancelledError, Exception):
            pass


app = FastAPI(title="P-Sieve", lifespan=lifespan)

# Kích hoạt CORS có kiểm soát: Giới hạn danh sách Origin và hỗ trợ Chrome/Edge Extension
cors_origins = settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS else ["http://localhost:8000", "http://127.0.0.1:8000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Session dua tren cookie (HttpOnly).
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(pages.router)
app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(chat.router)
app.include_router(api_v1.router)
