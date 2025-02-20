import pytest
from sqlalchemy.orm import Session
from python.database import AccessUserDatabase, User


@pytest.fixture(scope="function")
def access_db():
    """
    Fixture to provide an instance of the AccessUserDatabase with an in-memory database.
    """
    return AccessUserDatabase(db_url="sqlite:///:memory:")


@pytest.fixture(scope="function")
def db_session(access_db):
    """Fixture to provide a SQLAlchemy session. Closes once test is over"""
    session = Session(bind=access_db.engine)
    yield session
    session.close()


@pytest.fixture(scope="function")
def create_user(db_session):
    """
    Helper fixture to add a user to the in-memory database using the User model.
    """
    user = User(
        username="testuser",
        email="testuser@example.com",
        password_hash="hashed_password",
    )
    db_session.add(user)
    db_session.commit()
