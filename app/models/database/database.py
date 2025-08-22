from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.configuration import Configuration


class Base(DeclarativeBase):
    pass


config = Configuration.get_config()
postgres_config = config.postgres

DATABASE = {
    "drivername": "postgresql",
    "host": postgres_config.host,
    "port": postgres_config.port,
    "username": postgres_config.user,
    "password": postgres_config.password,
    "database": postgres_config.database,
}


def db_connect():
    """
    Create a database connection using the configuration.
    """
    return create_engine(URL.create(**DATABASE))


def create_deals_table(engine):
    Base.metadata.create_all(bind=engine)


def db_session():
    engine = db_connect()
    create_deals_table(engine)
    session = sessionmaker(bind=engine)
    return session()


def get_db():
    db = db_session()
    try:
        yield db
    finally:
        db.close()
