from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from ..config import settings

_url = settings.database_url
if _url.startswith("sqlite:///") and ":memory:" not in _url:
    Path(_url[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(_url, connect_args={"check_same_thread": False} if _url.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import tables  # noqa: F401  (register models)
    Base.metadata.create_all(engine)


def get_db():
    with SessionLocal() as session:
        yield session
