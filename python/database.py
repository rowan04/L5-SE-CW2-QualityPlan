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
        self.engine = create_engine(db_url, echo=True)
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
                with DuplicateRecordError as exc:
                    exc.response_detail = "Failed to add new user: "
                    +"email already in use"
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

            except IntegrityError as e:
                # The Integrity Error is raised from SQLAlchemy,
                # but we want to return a GetUserFromIdError.
                session.rollback()
                log.error("Error: %s", e.orig)
                with GetUserFromIdError as exc:
                    exc.response_detail = "Failed to delete user: "
                    +"user not found"
                    log.warning(exc.response_detail)
                    raise exc

            else:
                log.info("User with ID %s deleted.", user_id)

    def get_password(self, user_id):
        """
        Retrieves the password hash for a user.

        :param user_id: The user_id to query by.
        :return: the retrieved password hash if found.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    return user.password_hash

        except GetUserFromIdError as exc:
            exc.response_detail = "Failed to get password: user not found"
            log.warning(exc.response_detail)
            raise exc

    def get_username(self, user_id):
        """
        Retrieves the username for a user by their ID.

        :param user_id: The user_id to query by.
        :return: the retrieved username if found.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    return user.username

        except GetUserFromIdError as exc:
            exc.response_detail = "Failed to get username: user not found"
            log.warning(exc.response_detail)
            raise exc

    def get_email(self, user_id):
        """
        Retrieves the email for a user by their ID.

        :param user_id: The user_id to query by.
        :return: the retrieved email if found.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()

                if user:
                    return user.email

        except GetUserFromIdError as exc:
            exc.response_detail = "Failed to get email: user not found"
            log.info(exc.response_detail)
            raise exc

    def get_date_created(self, user_id):
        """
        Retrieves the creation date for a user by their ID.

        :param user_id: The user_id to query by.
        :return: the retrieved user creation date if found.
        :raises GetUserFromIdError: If the supplied `user_id`
            is not linked to a user, or is invalid.
        """
        try:
            with self.Session() as session:
                user = session.query(User).filter_by(id=user_id).first()
                if user:
                    return user.created_at

        except GetUserFromIdError as exc:
            exc.response_detail = "Failed to get creation date: user not found"
            log.info(exc.response_detail)
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
            try:
                user = session.query(User).filter_by(id=user_id).first()

            except IntegrityError as e:
                # The Integrity Error is raised from SQLAlchemy,
                # but we want to return a GetUserFromIdError.
                session.rollback()
                log.error("Error: %s", e.orig)
                with GetUserFromIdError as exc:
                    exc.response_detail = "Failed to update email: "
                    +"user not found"
                    log.info(exc.response_detail)
                    raise exc

            else:
                if user:
                    try:
                        user.email = new_email
                        session.commit()

                    except IntegrityError as e:
                        # The Integrity Error is raised from SQLAlchemy,
                        # but we want to return a DuplicateRecordError.
                        session.rollback()
                        log.error("Error: %s", e.orig)
                        with DuplicateRecordError as exc:
                            exc.response_detail = "Failed to update email: "
                            +"new email is already in use"
                            log.info(exc.response_detail)
                            raise exc

                    else:
                        log.info("User's email updated to %s", new_email)
