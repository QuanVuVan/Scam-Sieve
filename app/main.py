"""
Diem khoi dau cua ung dung ScamSieve.
Chay bang: uvicorn app.main:app --reload
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import Base, engine
from app.routers import pages, scan, reports, api_v1, chat

# Import cac model de SQLAlchemy Base.metadata "biet" ve tat ca cac bang
# truoc khi goi create_all(). Neu them model moi, nho import them o day.
# Dat alias "scan_model" vi ten module trung voi app.routers.scan da import o tren.
from app.models import user, blacklist, report, scan as scan_model  # noqa: F401

# Tao bang trong DB neu chua ton tai.
# Cach don gian, phu hop giai doan dev/hoc tap (xem README de biet ly do
# chua dung Alembic o buoc nay).
Base.metadata.create_all(bind=engine)

app = FastAPI(title="P-Sieve")

# Kich hoat CORS de Chrome Extension va Client co the ket noi den API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session dua tren cookie (HttpOnly). Dung cho dang nhap o Buoc 6.
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(pages.router)
app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(chat.router)
app.include_router(api_v1.router)


@app.on_event("startup")
def startup_load_threat_intelligence():
    """
    Tự động nạp toàn bộ danh sách đen tên miền từ SQLite vào bộ nhớ đệm RAM O(1) khi máy chủ khởi động.
    """
    from app.database import SessionLocal
    from app.services.blacklist_service import threat_intel
    db = SessionLocal()
    try:
        threat_intel.load_from_database(db)
    finally:
        db.close()

# Cac router sau se duoc them dan o cac buoc tiep theo:
# app.include_router(auth.router)      # Buoc 6
# app.include_router(history.router)   # Buoc 6
# app.include_router(reports.router)   # Buoc 6
# app.include_router(admin.router)     # Buoc 6
