from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine_options = {"pool_pre_ping": True, "pool_recycle": 1800}
if settings.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
    # Fail a blocked statement promptly. Do not set PostgreSQL's
    # idle_in_transaction timeout here: deployment workers intentionally keep
    # their unit of work open while remote build phases are running.
    engine_options["connect_args"] = {
        "options": "-c lock_timeout=15000",
    }
engine = create_engine(settings.database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

