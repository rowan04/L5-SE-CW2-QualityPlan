"""
Module for custom exception classes.
"""

from typing import Optional


class BaseException(Exception):
    """Base exceptions for errors across the smart home app."""

    # Generic detail of the exception (that may be returned in a response).
    response_detail: str

    detail: str

    def __init__(self, detail: str, response_detail: Optional[str] = None):
        """
        Initialise the exception.

        :param detail: Specific detail of the exception (just like Exception would take - this will only be logged and
            not returned in a response).
        :param response_detail: Generic detail of the exception that will be returned in a reponse.
        """
        super().__init__(detail)

        self.detail = detail

        if response_detail is not None:
            self.response_detail = response_detail


class DatabaseError(BaseException):
    """Database related error."""


class DatabaseIntegrityError(DatabaseError):
    """Exception raised when the relational integrity of the database is affected."""

    response_detail = "Database integrity error raised"


class DuplicateRecordError(DatabaseError):
    """Exception raised when a database record is a duplicate."""

    response_detail = "Database record is a duplicate"


class GetIdFromEmailError(DatabaseError):
    """Exception raised when the method to retrieve a user ID based on their email failed."""

    response_detail = "Failed to get user ID - user with entered email not found"


class GetUserFromIdError(DatabaseError):
    """Exception raised when the method to query a user based on their user ID failed."""

    response_detail = "User not found"
