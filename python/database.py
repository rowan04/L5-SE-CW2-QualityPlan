import logging

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError

log = logging.getLogger(__name__)
handler = logging.StreamHandler()  # Logs to the terminal
log.addHandler(handler)  # Adds handler to log
log.setLevel(logging.INFO)

# Base class for ORM models
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

    def __repr__(self):
        return (
            f"<User(id={self.id}, "
            f"username='{self.username}', "
            f"email='{self.email}')>"
        )


class AccessUserDatabase:
    def __init__(self, db_url="sqlite:///database/user_database.db"):
        self.engine = create_engine(db_url, echo=True)
        self.Session = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)

    def get_id_from_email(self, email):
        """
        Retrieves the user ID based on their email address.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(email=email).first()

                if user:
                    return user.id
                else:
                    log.error("User not found.")
                    return None
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def add_user(self, username, email, hashed_password):
        """
        Adds a new user to the database.
        """
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
        )

        # Using context manager to automatically handle session open/close
        with self.Session() as session:
            try:
                session.add(new_user)
                session.commit()
                log.info("User %s added successfully!", username)
            except IntegrityError as e:
                session.rollback()
                log.error("Error: %s", e.orig)
                log.error("Error: Email already exists.")

    def remove_user(self, user_id):
        """
        Removes a user from the database using their ID.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    session.delete(user)
                    session.commit()
                    log.info("User with ID %s deleted.", user_id)
                else:
                    log.error("User not found.")
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def get_password(self, user_id):
        """
        Retrieves the password hash for a user.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()
                if user:
                    return user.password_hash
                else:
                    log.error("User not found.")
                    return None
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def get_username(self, user_id):
        """
        Retrieves the username for a user by their ID.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()
                if user:
                    return user.username
                else:
                    log.error("User not found.")
                    return None
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def get_email(self, user_id):
        """
        Retrieves the email for a user by their ID.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()
                if user:
                    return user.email
                else:
                    log.error("User not found.")
                    return None
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def get_date_created(self, user_id):
        """
        Retrieves the creation date for a user by their ID.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()
                if user:
                    return user.created_at
                else:
                    log.error("User not found.")
                    return None
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"

    def update_email(self, user_id, new_email):
        """
        Updates the email of a user by ID.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    try:
                        user.email = new_email
                        session.commit()
                        log.info("User's email updated to %s", new_email)
                    except IntegrityError as e:
                        session.rollback()
                        log.error("Error: %s", e.orig)
                        log.error("Error: Email already exists.")
                else:
                    log.error("User not found.")
        except Exception as e:
            log.error("Unexpected error: %s", e)
            return "error"
