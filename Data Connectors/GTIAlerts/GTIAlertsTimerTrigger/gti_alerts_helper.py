"""Get GTI Alerts data and ingest into Microsoft Sentinel."""

import inspect
import re
import time
import datetime

from tenacity import RetryError

from SharedCode.utils import Utils
from SharedCode.logger import applogger
from SharedCode import consts
from SharedCode.exceptions import GTIAlertsException, GTIAlertsTimeoutException
from SharedCode.state_manager import StateManager
from SharedCode.sentinel import send_data_to_sentinel
from SharedCode.gti_client import GTIClient


CHECKPOINT_FILE_PATH = "gti_alerts_checkpoint"
FUNCTION_NAME = "GTIAlertsTimerTrigger"


class GTIAlertsHelper(Utils):
    """Helper class for ingesting Google Threat Intelligence alerts into Sentinel.

    Inherits from Utils for checkpoint and environment variable management.
    Orchestrates GTI API authentication, pagination, Sentinel ingestion,
    and checkpoint persistence.
    """

    def __init__(self, start_time: int) -> None:
        """Initialise the GTIAlertsHelper.

        Validates required environment variables, initialises the GTI client,
        and sets up the checkpoint StateManager.

        Args:
            start_time (int): Unix epoch timestamp of function start (for timeout guard).
        """
        super().__init__(FUNCTION_NAME)
        self.start = start_time
        self.gti_client = GTIClient()
        self.checkpoint_obj = StateManager(
            consts.CONN_STRING, CHECKPOINT_FILE_PATH, consts.FILE_SHARE_NAME
        )

    def get_gti_alerts_in_sentinel(self):
        """Fetch GTI alerts and ingest them into Microsoft Sentinel.

        Reads the last checkpoint timestamp, fetches alerts from the GTI API
        using cursor-based pagination, sends them to Sentinel in batches,
        and updates the checkpoint after each page to support resumable execution.

        Raises:
            GTIAlertsTimeoutException: If approaching the Azure Function timeout limit.
            GTIAlertsException: For any unrecoverable error during the ingestion workflow.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            # Determine the start timestamp for this run
            checkpoint_data = self.get_checkpoint_data(self.checkpoint_obj)
            if checkpoint_data:
                last_checkpoint = checkpoint_data.get("last_checkpoint")
            else:
                last_checkpoint = self.get_start_date_of_data_fetching()

            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Starting GTI alerts ingestion from checkpoint: {}".format(last_checkpoint),
                )
            )

            self._fetch_and_ingest_alerts(last_checkpoint)

        except GTIAlertsTimeoutException:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Function approaching 9:30-minute timeout limit, stopping gracefully.",
                )
            )
            return
        except GTIAlertsException:
            raise
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    consts.UNEXPECTED_ERROR_MSG.format(err),
                )
            )
            raise GTIAlertsException(
                "Unexpected error during GTI alerts ingestion: {}".format(err)
            )

    def _build_filter_expression(self, last_checkpoint: str) -> str:
        """Build the GTI API filter expression combining the checkpoint time and optional user filter.

        The base filter is always: audit.update_time >= "<checkpoint>".
        If GTI_FILTER_EXPRESSION is set, each AND-separated clause is inspected and
        any clause containing audit.update_time is dropped (it conflicts with the
        checkpoint filter). The remaining clauses are then combined with the base
        filter using AND.

        Example:
            user filter : 'detail.insider_threat.severity = "HIGH" and audit.update_time >= "2026-04-03T00:00:00Z"'
            effective   : 'audit.update_time >= "<checkpoint>" and detail.insider_threat.severity = "HIGH"'

        Args:
            last_checkpoint (str): ISO 8601 checkpoint timestamp.

        Returns:
            str: The combined filter expression ready to pass to the GTI API.
        """
        __method_name = inspect.currentframe().f_code.co_name
        base_filter = 'audit.update_time >= "{}"'.format(last_checkpoint)
        user_filter = consts.GTI_FILTER_EXPRESSION.strip()

        if not user_filter:
            return base_filter

        # Split on AND (case-insensitive), strip each clause, drop any containing audit.update_time
        clauses = re.split(r'\s+and\s+', user_filter, flags=re.IGNORECASE)
        kept = [c.strip() for c in clauses if "audit.update_time" not in c.lower()]
        removed = [c.strip() for c in clauses if "audit.update_time" in c.lower()]

        if removed:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Removed audit.update_time clause(s) from user filter: {}".format(removed),
                )
            )

        if not kept:
            return base_filter

        combined = "{} and {}".format(base_filter, " and ".join(kept))
        applogger.info(
            self.log_format.format(
                consts.LOGS_STARTS_WITH,
                __method_name,
                self.azure_function_name,
                "Combined filter expression: {}".format(combined),
            )
        )
        return combined

    def _fetch_and_ingest_alerts(self, last_checkpoint: str):
        """Paginate through GTI alerts and ingest them into Sentinel.

        Iterates through all pages of GTI alerts since the given checkpoint timestamp.
        Saves the checkpoint incrementally after processing each batch to support
        resuming after a timeout or crash. The checkpoint is updated to the
        updateTime of the most recent alert in each page.

        Args:
            last_checkpoint (str): ISO 8601 timestamp to filter alerts from.

        Raises:
            GTIAlertsTimeoutException: If approaching the Azure Function timeout limit.
            GTIAlertsException: For API errors or ingestion failures.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            filter_expr = self._build_filter_expression(last_checkpoint)
            page_token = None
            page_number = 0
            total_ingested = 0
            latest_checkpoint = last_checkpoint

            while True:
                if int(time.time()) >= self.start + consts.FUNCTION_APP_TIMEOUT_SECONDS:
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Timeout guard triggered at page {}, checkpoint saved at: {}".format(
                                page_number, latest_checkpoint
                            ),
                        )
                    )
                    raise GTIAlertsTimeoutException(
                        "Function timeout limit reached after page {}".format(page_number)
                    )

                page_number += 1
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Fetching page {}, page_token_present={}".format(
                            page_number, bool(page_token)
                        ),
                    )
                )

                try:
                    response = self.gti_client.list_alerts(
                        filter_expr=filter_expr,
                        page_token=page_token,
                    )
                except RetryError as error:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            consts.MAX_RETRY_ERROR_MSG.format(
                                error, error.last_attempt.exception()
                            ),
                        )
                    )
                    raise GTIAlertsException(
                        "Max retries exceeded fetching GTI alerts: {}".format(error)
                    )

                alerts = response.get("alerts", [])
                next_page_token = response.get("nextPageToken")

                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Page {} received {} alerts, has_next_page={}".format(
                            page_number, len(alerts), bool(next_page_token)
                        ),
                    )
                )

                if alerts:
                    send_data_to_sentinel(alerts, consts.GTI_ALERTS_TABLE_NAME)
                    total_ingested += len(alerts)
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Ingested {} alerts, total ingested so far: {}".format(
                                len(alerts), total_ingested
                            ),
                        )
                    )

                    # Response is ordered by audit.update_time asc, so the last alert
                    # in the page has the newest updateTime — use it as the checkpoint.
                    last_update_time = alerts[-1].get("audit", {}).get("updateTime", "")
                    if last_update_time and last_update_time > latest_checkpoint:
                        latest_checkpoint = last_update_time

                    self.post_checkpoint_data(
                        self.checkpoint_obj,
                        {"last_checkpoint": latest_checkpoint},
                    )

                if not next_page_token:
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "No next page token found, pagination complete. "
                            "Total alerts ingested: {}".format(total_ingested),
                        )
                    )
                    # Advance the checkpoint to now to avoid re-fetching old alerts next run
                    run_end_time = datetime.datetime.utcnow().strftime(consts.DATE_TIME_FORMAT)
                    if run_end_time > latest_checkpoint:
                        latest_checkpoint = run_end_time
                    self.post_checkpoint_data(
                        self.checkpoint_obj,
                        {"last_checkpoint": latest_checkpoint},
                    )
                    break

                page_token = next_page_token

        except GTIAlertsTimeoutException:
            raise
        except GTIAlertsException:
            raise
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    consts.UNEXPECTED_ERROR_MSG.format(err),
                )
            )
            raise GTIAlertsException(
                "Unexpected error during alert pagination and ingestion: {}".format(err)
            )

