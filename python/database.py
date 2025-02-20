"""
Module for connecting to an SQLAlchemy database.
"""

import logging

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from python.exceptions import (
    GetIdFromEmailError,
    DuplicateRecordError,
    GetUserFromIdError,
)

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
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)

    def get_id_from_email(self, email):
        """
        Retrieves the user ID based on their email address.

        :param email: The email to query by.
        :return: the retrieved user ID if found.
        :raises GetIdFromEmailError: If the supplied `email`
            is not associated with a user, or is invalid.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(email=email).first()

                if user:
                    return user.id
                raise GetIdFromEmailError(f"User with email {email} not found")

        except GetIdFromEmailError as exc:
            log.warning(exc.response_detail)
            raise exc

    def add_user(self, username, email, hashed_password):
        """
        Adds a new user to the database.

        :param username: The username of the new user.
        :param email: The email of the new user.
        :param hashed_password: The hashed password of the new user.
        :raises DuplicateRecordError: If the supplied `email`
            is already in use.
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

            except IntegrityError as e:
                # The Integrity Error is raised from SQLAlchemy,
                # but we want to return a DuplicateRecordError.
                session.rollback()
                log.error("Error: %s", e.orig)
                exc = DuplicateRecordError(
                    "Failed to add new user: email already in use"
                )
                log.warning(exc.response_detail)
                raise exc

            else:
                log.info("User %s added successfully!", username)

    def remove_user(self, user_id):
        """
        Removes a user from the database using their ID.

        :param user_id: The user_id to query by.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        with self.Session() as session:
            try:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    session.delete(user)
                    session.commit()
                    log.info("User with ID %s deleted.", user_id)
                else:
                    # Raise the error if the user is not found
                    raise GetUserFromIdError(f"User with ID {user_id} not found")

            except IntegrityError as e:
                session.rollback()
                log.error("Error: %s", e.orig)
                raise e

    def get_user_info(self, user_id, field=None):
        """
        Retrieves specific information for a user by their ID.

        :param user_id: The user_id to query by.
        :param field: The field to retrieve
            (e.g., 'password_hash', 'username', 'email', 'created_at').
        :return: the requested information if found.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        :raises ValueError: If the supplied `field` does not exist in the user model
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    # If no field is provided, return the entire user object
                    if field is None:
                        return user
                    # Ensure the requested field is valid and return it
                    elif hasattr(user, field):
                        return getattr(user, field)
                    else:
                        raise ValueError(f"Invalid field: {field}")

                # If no user is found
                raise GetUserFromIdError(f"User with ID {user_id} not found")

        except GetUserFromIdError:
            log.warning("Failed to get user information: user not found")
            raise
        except ValueError as exc:
            log.warning(str(exc))
            raise exc

    def update_email(self, user_id, new_email):
        """
        Updates the email of a user by ID.

        :param user_id: The user_id to query by.
        :param new_email: The new email to be set for the user.
        :raises DuplicateRecordError: If the supplied `new_email`
            is already in use.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        with self.Session() as session:
            user = self.get_user_info(user_id=user_id)

            if user:
                try:
                    session.add(user)
                    user.email = new_email
                    session.commit()

                except Exception as e:
                    # Handle any database errors, rollback the session
                    session.rollback()
                    log.error("Error: %s", str(e))
                    raise e

                else:
                    # Log the success
                    log.info("User's email updated to %s", new_email)
