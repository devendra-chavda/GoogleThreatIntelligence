"""This file contains custom exception classes for the Google Threat Intelligence connector."""


class GTIAlertsException(Exception):
    """Exception class to handle Google Threat Intelligence Alerts connector exceptions.

    Args:
        Exception (string): Will print exception message.
    """

    def __init__(self, message=None) -> None:
        """Initialize custom GTI Alerts exception with custom message."""
        super().__init__(message)


class GTIAlertsTimeoutException(Exception):
    """Exception class to handle Google Threat Intelligence Alerts function timeout.

    Raised when the Azure Function approaches the 9:30-minute execution limit.

    Args:
        Exception (string): Will print exception message.
    """

    def __init__(self, message=None) -> None:
        """Initialize custom GTI Alerts timeout exception with custom message."""
        super().__init__(message)


class GTIAlertsAuthException(Exception):
    """Exception class to handle Google Threat Intelligence authentication failures.

    Raised when token exchange fails or credentials are invalid.

    Args:
        Exception (string): Will print exception message.
    """

    def __init__(self, message=None) -> None:
        """Initialize custom GTI Alerts authentication exception with custom message."""
        super().__init__(message)
