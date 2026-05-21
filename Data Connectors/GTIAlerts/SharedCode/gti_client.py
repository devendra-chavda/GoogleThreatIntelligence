"""GTI API client for Google Threat Intelligence connector.

Handles token exchange, token caching, and alert pagination for the GTI API.
"""

import inspect
import time
import requests
from json.decoder import JSONDecodeError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_result,
    retry_any,
    RetryError,
)
from requests.exceptions import ConnectionError as RequestsConnectionError

from SharedCode.logger import applogger
from SharedCode import consts
from SharedCode.exceptions import GTIAlertsException, GTIAlertsAuthException


def _retry_on_status_code(response):
    """Check whether the response requires a retry based on status code.

    Args:
        response: The HTTP response object or dict.

    Returns:
        bool: True if the response should be retried, False otherwise.
    """
    __method_name = inspect.currentframe().f_code.co_name
    if isinstance(response, dict):
        return False
    if response.status_code in consts.RETRY_STATUS_CODE:
        applogger.info(
            consts.LOG_FORMAT.format(
                consts.LOGS_STARTS_WITH,
                __method_name,
                "GTIClient",
                "Retrying due to status code: {}".format(response.status_code),
            )
        )
        return True
    return False


class GTIClient:
    """Google Threat Intelligence API client.

    Manages Bearer token lifecycle (exchange and refresh) and provides
    methods to list GTI alerts with cursor-based pagination.
    """

    def __init__(self):
        """Initialize the GTI client with empty token state."""
        self._access_token = None
        self._token_expiry = 0

    def _is_token_expired(self):
        """Check whether the current access token is expired or near expiry.

        Returns:
            bool: True if token should be refreshed, False if still valid.
        """
        return time.time() >= (self._token_expiry - consts.TOKEN_EXPIRY_BUFFER_SECONDS)

    @retry(
        stop=stop_after_attempt(consts.MAX_RETRIES),
        wait=wait_exponential(
            multiplier=consts.BACKOFF_MULTIPLIER,
            min=consts.MIN_SLEEP_TIME,
            max=consts.MAX_SLEEP_TIME,
        ),
        retry=retry_any(
            retry_if_result(_retry_on_status_code),
            retry_if_exception_type(RequestsConnectionError),
        ),
        before_sleep=lambda retry_state: applogger.error(
            "{}(method = {}) : Retrying after {} seconds, attempt number: {}".format(
                consts.LOGS_STARTS_WITH,
                "GTIClient._exchange_api_key",
                retry_state.upcoming_sleep,
                retry_state.attempt_number,
            )
        ),
    )
    def _exchange_api_key(self):
        """Exchange GTI API key for a Bearer access token.

        Calls the GTI IdP token exchange endpoint with the API key and
        caches the resulting token and its expiry time.

        Raises:
            GTIAlertsAuthException: If token exchange fails or API key is invalid.
            GTIAlertsException: For unexpected errors during token exchange.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    "Exchanging GTI API key for Bearer token",
                )
            )
            response = requests.request(
                method="POST",
                url=consts.GTI_TOKEN_EXCHANGE_URL,
                data={"api_key": consts.GTI_API_KEY},
                headers={"Content-Type": "application/json"},
                timeout=consts.MAX_TIMEOUT_SENTINEL,
            )

            if response.status_code == 200:
                response_json = response.json()
                self._access_token = response_json.get("access_token")
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Successfully response_json={}s".format(response_json),
                    )
                )
                expires_in = response_json.get("expires_in", 3600)
                self._token_expiry = time.time() + expires_in
                if not self._access_token:
                    applogger.error(
                        consts.LOG_FORMAT.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            "GTIClient",
                            "Token exchange response missing 'access_token' field",
                        )
                    )
                    raise GTIAlertsAuthException(
                        "Token exchange response missing 'access_token' field"
                    )
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Successfully obtained GTI Bearer token, expires_in={}s".format(expires_in),
                    )
                )
                return
            elif response.status_code == 401:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Token exchange returned 401 Unauthorized - invalid GTI API key",
                    )
                )
                raise GTIAlertsAuthException(
                    "GTI token exchange returned 401 Unauthorized: invalid API key"
                )
            elif response.status_code == 403:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Token exchange returned 403 Forbidden. Response: {}".format(response.text),
                    )
                )
                raise GTIAlertsAuthException(
                    "GTI token exchange returned 403 Forbidden: {}".format(response.text)
                )
            elif response.status_code in consts.RETRY_STATUS_CODE:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Token exchange returned retryable status code: {}".format(
                            response.status_code
                        ),
                    )
                )
                return response
            else:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Token exchange returned unexpected status code: {}. Response: {}".format(
                            response.status_code, response.text
                        ),
                    )
                )
                raise GTIAlertsAuthException(
                    "GTI token exchange failed with status {}: {}".format(
                        response.status_code, response.text
                    )
                )

        except GTIAlertsAuthException:
            raise
        except requests.exceptions.Timeout as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.TIME_OUT_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "Timeout during GTI token exchange: {}".format(error)
            )
        except RequestsConnectionError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.CONNECTION_ERROR_MSG.format(error),
                )
            )
            raise RequestsConnectionError(
                "Connection error during GTI token exchange: {}".format(error)
            )
        except JSONDecodeError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.JSON_DECODE_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "JSON decode error during GTI token exchange: {}".format(error)
            )
        except Exception as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.UNEXPECTED_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "Unexpected error during GTI token exchange: {}".format(error)
            )

    def ensure_authenticated(self):
        """Ensure a valid Bearer token is available, refreshing if necessary.

        Calls token exchange if the current token is missing or near expiry.

        Raises:
            GTIAlertsAuthException: If token exchange fails.
            GTIAlertsException: For unexpected errors.
        """
        __method_name = inspect.currentframe().f_code.co_name
        if self._access_token is None or self._is_token_expired():
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    "Token is missing or expired, performing token exchange",
                )
            )
            try:
                self._exchange_api_key()
            except RetryError as error:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        consts.MAX_RETRY_ERROR_MSG.format(
                            error, error.last_attempt.exception()
                        ),
                    )
                )
                raise GTIAlertsAuthException(
                    "Max retries exceeded during GTI token exchange: {}".format(error)
                )

    @retry(
        stop=stop_after_attempt(consts.MAX_RETRIES),
        wait=wait_exponential(
            multiplier=consts.BACKOFF_MULTIPLIER,
            min=consts.MIN_SLEEP_TIME,
            max=consts.MAX_SLEEP_TIME,
        ),
        retry=retry_any(
            retry_if_result(_retry_on_status_code),
            retry_if_exception_type(RequestsConnectionError),
        ),
        before_sleep=lambda retry_state: applogger.error(
            "{}(method = {}) : Retrying after {} seconds, attempt number: {}".format(
                consts.LOGS_STARTS_WITH,
                "GTIClient.list_alerts",
                retry_state.upcoming_sleep,
                retry_state.attempt_number,
            )
        ),
    )
    def list_alerts(self, project, filter_expr=None, page_token=None, page_size=None):
        """List GTI alerts for a project, with optional filtering and pagination.

        On the first page (no page_token), passes filter_expr and orderBy parameters.
        On continuation pages (page_token provided), passes only the pageToken parameter
        as required by the GTI API.

        Args:
            project (str): The GTI project ID.
            filter_expr (str, optional): Filter expression using snake_case field names
                (e.g., 'audit.create_time >= "2024-01-01T00:00:00Z"').
            page_token (str, optional): Continuation token from a previous response.
            page_size (int, optional): Number of results per page (max 1000).

        Returns:
            dict: The JSON response containing 'alerts' list and optional 'nextPageToken'.

        Raises:
            GTIAlertsException: For API errors that should not be retried.
            GTIAlertsAuthException: If authentication fails.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            self.ensure_authenticated()
            url = "{}/{}/projects/{}/alerts".format(
                consts.GTI_BASE_URL, consts.GTI_API_VERSION, project
            )
            headers = {
                "Authorization": "Bearer {}".format(self._access_token),
                "x-goog-user-project": project,
                "Content-Type": "application/json",
            }

            if page_token:
                # Continuation request: only pageToken, no filter or orderBy
                params = {"pageToken": page_token}
            else:
                # First request: include filter and ordering
                params = {"pageSize": page_size or consts.PAGE_SIZE}
                if filter_expr:
                    params["filter"] = filter_expr
                    params["orderBy"] = "audit.create_time asc"

            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    "Calling GTI alerts API, url={}, page_token_present={}".format(
                        url, bool(page_token)
                    ),
                )
            )

            response = requests.request(
                method="GET",
                url=url,
                headers=headers,
                params=params,
                timeout=consts.MAX_TIMEOUT_SENTINEL,
            )

            if response.status_code == 200:
                response_json = response.json()
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Successfully received alerts response, alerts_count={}".format(
                            len(response_json.get("alerts", []))
                        ),
                    )
                )
                return response_json

            elif response.status_code == 400:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Bad Request (400): filter syntax error or invalid pageSize. Response: {}".format(
                            response.text
                        ),
                    )
                )
                raise GTIAlertsException(
                    "GTI API returned 400 Bad Request: {}".format(response.text)
                )

            elif response.status_code == 401:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Unauthorized (401): token expired or invalid. Refreshing token and retrying once.",
                    )
                )
                # Force token refresh
                self._access_token = None
                self._token_expiry = 0
                self.ensure_authenticated()
                # Retry the request once with refreshed token
                headers["Authorization"] = "Bearer {}".format(self._access_token)
                retry_response = requests.request(
                    method="GET",
                    url=url,
                    headers=headers,
                    params=params,
                    timeout=consts.MAX_TIMEOUT_SENTINEL,
                )
                if retry_response.status_code == 200:
                    return retry_response.json()
                else:
                    applogger.error(
                        consts.LOG_FORMAT.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            "GTIClient",
                            "Retry after 401 also failed with status: {}. Response: {}".format(
                                retry_response.status_code, retry_response.text
                            ),
                        )
                    )
                    raise GTIAlertsException(
                        "GTI API retry after 401 failed with status {}: {}".format(
                            retry_response.status_code, retry_response.text
                        )
                    )

            elif response.status_code == 403:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Forbidden (403): wrong project ID or inactive GTI subscription. Response: {}".format(
                            response.text
                        ),
                    )
                )
                raise GTIAlertsException(
                    "GTI API returned 403 Forbidden: {}".format(response.text)
                )

            elif response.status_code == 429:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Too Many Requests (429): rate limit exceeded. Will retry with backoff.",
                    )
                )
                return response

            elif response.status_code in [500, 502, 503, 509]:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Server error ({}): transient error. Will retry with backoff.".format(
                            response.status_code
                        ),
                    )
                )
                return response

            else:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        "GTIClient",
                        "Unexpected status code: {}. Response: {}".format(
                            response.status_code, response.text
                        ),
                    )
                )
                raise GTIAlertsException(
                    "GTI API returned unexpected status {}: {}".format(
                        response.status_code, response.text
                    )
                )

        except GTIAlertsException:
            raise
        except GTIAlertsAuthException:
            raise
        except requests.exceptions.Timeout as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.TIME_OUT_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "Timeout during GTI alerts API call: {}".format(error)
            )
        except RequestsConnectionError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.CONNECTION_ERROR_MSG.format(error),
                )
            )
            raise RequestsConnectionError(
                "Connection error during GTI alerts API call: {}".format(error)
            )
        except JSONDecodeError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.JSON_DECODE_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "JSON decode error during GTI alerts API call: {}".format(error)
            )
        except Exception as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    "GTIClient",
                    consts.UNEXPECTED_ERROR_MSG.format(error),
                )
            )
            raise GTIAlertsException(
                "Unexpected error during GTI alerts API call: {}".format(error)
            )
