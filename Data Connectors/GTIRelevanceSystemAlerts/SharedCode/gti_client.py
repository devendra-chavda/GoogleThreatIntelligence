"""GTI API client for Google Threat Intelligence connector.

Handles token exchange, token caching, and alert pagination for the GTI API.
"""

import inspect
import time
import json
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
from SharedCode.exceptions import GTIRelevanceSystemAlertsException, GTIRelevanceSystemAlertsAuthException


def _retry_on_status_code(response):
    """Check whether the response requires a retry based on status code.

    Args:
        response: The HTTP response object or dict.

    Returns:
        bool: True if the response should be retried, False otherwise.
    """
    __method_name = inspect.currentframe().f_code.co_name
    if response is None or isinstance(response, dict):
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
            GTIRelevanceSystemAlertsAuthException: If token exchange fails or API key is invalid.
            GTIRelevanceSystemAlertsException: For unexpected errors during token exchange.
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
            payload = json.dumps({
                "api_key": consts.GTI_API_KEY
            })
            response = requests.request(
                method="POST",
                url=consts.GTI_TOKEN_EXCHANGE_URL,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Azure-Sentinel-GTIRelevanceSystemAlerts/1.0.0",
                },
                timeout=consts.MAX_TIMEOUT_SENTINEL,
            )

            if response.status_code == 200:
                response_json = response.json()
                self._access_token = response_json.get("access_token")
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
                    raise GTIRelevanceSystemAlertsAuthException(
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
                raise GTIRelevanceSystemAlertsAuthException(
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
                raise GTIRelevanceSystemAlertsAuthException(
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
                raise GTIRelevanceSystemAlertsAuthException(
                    "GTI token exchange failed with status {}: {}".format(
                        response.status_code, response.text
                    )
                )

        except GTIRelevanceSystemAlertsAuthException:
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
            raise GTIRelevanceSystemAlertsException(
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
            raise GTIRelevanceSystemAlertsException(
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
            raise GTIRelevanceSystemAlertsException(
                "Unexpected error during GTI token exchange: {}".format(error)
            )

    def ensure_authenticated(self):
        """Ensure a valid Bearer token is available, refreshing if necessary.

        Calls token exchange if the current token is missing or near expiry.

        Raises:
            GTIRelevanceSystemAlertsAuthException: If token exchange fails.
            GTIRelevanceSystemAlertsException: For unexpected errors.
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
                raise GTIRelevanceSystemAlertsAuthException(
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
    def _get_headers(self):
        """Build request headers using the current access token."""
        return {
            "Authorization": "Bearer {}".format(self._access_token),
            "x-goog-user-project": consts.GTI_PROJECT_ID,
            "Content-Type": "application/json",
            "User-Agent": "Azure-Sentinel-GTIRelevanceSystemAlerts/1.0.0",
        }

    def _handle_response(self, response, method_name):
        """Interpret an HTTP response, returning parsed JSON or raising/returning for retry.

        Returns:
            dict: Parsed JSON on HTTP 200.
            requests.Response: Returned as-is for retryable status codes so the
                @retry decorator triggers retry_if_result(_retry_on_status_code).

        Raises:
            GTIRelevanceSystemAlertsException: For 400, 403, and unexpected status codes.
        """
        if response.status_code == 200:
            response_json = response.json()
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, method_name, "GTIClient",
                    "Received {} alerts".format(len(response_json.get("alerts", []))),
                )
            )
            return response_json

        if response.status_code == 400:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, method_name, "GTIClient",
                    "Bad Request (400): filter syntax error. Response: {}".format(response.text),
                )
            )
            raise GTIRelevanceSystemAlertsException("GTI API returned 400 Bad Request: {}".format(response.text))

        if response.status_code == 403:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, method_name, "GTIClient",
                    "Forbidden (403): wrong project ID or inactive GTI subscription. Response: {}".format(
                        response.text
                    ),
                )
            )
            raise GTIRelevanceSystemAlertsException("GTI API returned 403 Forbidden: {}".format(response.text))

        if response.status_code in consts.RETRY_STATUS_CODE:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, method_name, "GTIClient",
                    "Retryable status code {}: will retry with backoff.".format(response.status_code),
                )
            )
            return response

        applogger.error(
            consts.LOG_FORMAT.format(
                consts.LOGS_STARTS_WITH, method_name, "GTIClient",
                "Unexpected status code {}: {}".format(response.status_code, response.text),
            )
        )
        raise GTIRelevanceSystemAlertsException(
            "GTI API returned unexpected status {}: {}".format(response.status_code, response.text)
        )

    def list_alerts(self, filter_expr=None, page_token=None):
        """Fetch one page of GTI alerts.

        Always sends pageSize and orderBy. Includes filter_expr when provided.
        Includes pageToken on continuation pages.

        Args:
            filter_expr (str, optional): GTI API filter expression
                (e.g. 'audit.update_time >= "2026-01-01T00:00:00Z" and state = "OPEN"').
            page_token (str, optional): Continuation token returned by the previous page.

        Returns:
            dict: JSON response with 'alerts' list and optional 'nextPageToken'.

        Raises:
            GTIRelevanceSystemAlertsException: For non-retryable API errors.
            GTIRelevanceSystemAlertsAuthException: If authentication fails.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            self.ensure_authenticated()

            url = "{}/{}/projects/{}/alerts".format(
                consts.GTI_BASE_URL, consts.GTI_API_VERSION, consts.GTI_PROJECT_ID
            )

            params = {
                "pageSize": consts.PAGE_SIZE,
                "orderBy": "audit.update_time asc",
            }
            if filter_expr:
                params["filter"] = filter_expr
            if page_token:
                params["pageToken"] = page_token

            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                    "Calling GTI alerts API, page_token_present={}".format(bool(page_token)),
                )
            )

            response = requests.get(
                url=url,
                headers=self._get_headers(),
                params=params,
                timeout=consts.MAX_TIMEOUT_SENTINEL,
            )

            if response.status_code == 401:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                        "Unauthorized (401): refreshing token and retrying once.",
                    )
                )
                self._access_token = None
                self._token_expiry = 0
                self.ensure_authenticated()
                response = requests.get(
                    url=url,
                    headers=self._get_headers(),
                    params=params,
                    timeout=consts.MAX_TIMEOUT_SENTINEL,
                )
                if response.status_code != 200:
                    raise GTIRelevanceSystemAlertsException(
                        "GTI API retry after 401 failed with status {}: {}".format(
                            response.status_code, response.text
                        )
                    )

            return self._handle_response(response, __method_name)

        except (GTIRelevanceSystemAlertsException, GTIRelevanceSystemAlertsAuthException):
            raise
        except requests.exceptions.Timeout as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                    consts.TIME_OUT_ERROR_MSG.format(error),
                )
            )
            raise GTIRelevanceSystemAlertsException("Timeout during GTI alerts API call: {}".format(error))
        except RequestsConnectionError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                    consts.CONNECTION_ERROR_MSG.format(error),
                )
            )
            raise RequestsConnectionError(
                "Connection error during GTI alerts API call: {}".format(error)
            )
        except JSONDecodeError as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                    consts.JSON_DECODE_ERROR_MSG.format(error),
                )
            )
            raise GTIRelevanceSystemAlertsException("JSON decode error during GTI alerts API call: {}".format(error))
        except Exception as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH, __method_name, "GTIClient",
                    consts.UNEXPECTED_ERROR_MSG.format(error),
                )
            )
            raise GTIRelevanceSystemAlertsException("Unexpected error during GTI alerts API call: {}".format(error))
