"""Utils module for Google Threat Intelligence connector.

Provides the Utils base class with checkpoint management and date helper utilities.
"""

import inspect
import json
import datetime
from json.decoder import JSONDecodeError

from SharedCode.state_manager import StateManager
from SharedCode.exceptions import GTIAlertsException
from SharedCode.logger import applogger
from SharedCode import consts


class Utils:
    """Base utility class for the GTI connector.

    Provides checkpoint management and date helper methods
    shared across GTI connector functions.
    """

    def __init__(self, azure_function_name: str) -> None:
        """Initialise the Utils base class.

        Args:
            azure_function_name (str): Name of the Azure Function using this class.
        """
        self.azure_function_name = azure_function_name
        self.log_format = consts.LOG_FORMAT

    def check_environment_var_exist(self, environment_var):
        """Check the existence of required environment variables.

        Logs the validation process and completion. Raises GTIAlertsException
        if any required variable is missing.

        Args:
            environment_var (list): List of dicts mapping variable name to value.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Validating Environment Variables",
                )
            )
            missing_required_field = False
            for var in environment_var:
                key, val = next(iter(var.items()))
                if not val:
                    missing_required_field = True
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Environment variable {} is not set".format(key),
                        )
                    )
            if missing_required_field:
                applogger.error(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Validation failed: one or more required environment variables are missing",
                    )
                )
                raise GTIAlertsException(
                    "One or more required environment variables are missing"
                )
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Environment variable validation complete",
                )
            )
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
                "Unexpected error during environment variable validation: {}".format(err)
            )

    def get_checkpoint_data(self, checkpoint_obj: StateManager, load_flag=True):
        """Get checkpoint data from a StateManager object.

        Args:
            checkpoint_obj (StateManager): The StateManager object to retrieve checkpoint data from.
            load_flag (bool): A flag indicating whether to load the data as JSON (default is True).

        Returns:
            dict or str or None: The retrieved checkpoint data.

        Raises:
            GTIAlertsException: If there is an error reading or parsing checkpoint data.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Fetching checkpoint data",
                )
            )
            checkpoint_data = checkpoint_obj.get()
            if load_flag and checkpoint_data:
                checkpoint_data = json.loads(checkpoint_data)
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Checkpoint data = {}".format(checkpoint_data),
                )
            )
            return checkpoint_data
        except JSONDecodeError as json_error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    consts.JSON_DECODE_ERROR_MSG.format(json_error),
                )
            )
            raise GTIAlertsException(
                "JSON decode error reading checkpoint: {}".format(json_error)
            )
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
                "Unexpected error reading checkpoint: {}".format(err)
            )

    def post_checkpoint_data(self, checkpoint_obj: StateManager, data, dump_flag=True):
        """Post checkpoint data to a StateManager object.

        Args:
            checkpoint_obj (StateManager): The StateManager object to post data to.
            data: The data to be posted.
            dump_flag (bool): Whether to JSON-serialise data before posting (default is True).

        Raises:
            GTIAlertsException: If there is an error writing checkpoint data.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Posting checkpoint data = {}".format(data),
                )
            )
            if dump_flag:
                checkpoint_obj.post(json.dumps(data))
            else:
                checkpoint_obj.post(data)
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Checkpoint data posted to Azure Storage",
                )
            )
        except TypeError as type_error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    consts.TYPE_ERROR_MSG.format(type_error),
                )
            )
            raise GTIAlertsException(
                "Type error posting checkpoint: {}".format(type_error)
            )
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
                "Unexpected error posting checkpoint: {}".format(err)
            )

    def get_start_date_of_data_fetching(self):
        """Retrieve the start date for data fetching.

        If no start date is configured via StartDate environment variable, calculates
        a default lookback window of DEFAULT_LOOKUP_DAYS days from now.
        If a start date is provided but is invalid or in the future, raises an exception.

        Returns:
            str: The start date for data fetching in DATE_TIME_FORMAT.

        Raises:
            GTIAlertsException: If the start date is invalid or in the future.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            if not consts.START_DATE:
                start_date = (
                    datetime.datetime.utcnow()
                    - datetime.timedelta(days=consts.DEFAULT_LOOKUP_DAYS)
                ).strftime(consts.DATE_TIME_FORMAT)
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "No StartDate configured, defaulting to {} days lookback: {}".format(
                            consts.DEFAULT_LOOKUP_DAYS, start_date
                        ),
                    )
                )
                return start_date
            try:
                start_date = datetime.datetime.strptime(
                    consts.START_DATE, "%Y-%m-%d"
                ).strftime(consts.DATE_TIME_FORMAT)
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Start date configured by user: {}".format(start_date),
                    )
                )
                if start_date > datetime.datetime.utcnow().strftime(consts.DATE_TIME_FORMAT):
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Configured StartDate is a future date: {}".format(start_date),
                        )
                    )
                    raise GTIAlertsException(
                        "StartDate '{}' is in the future".format(start_date)
                    )
                return start_date
            except ValueError:
                applogger.error(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "StartDate '{}' is not a valid date in yyyy-mm-dd format".format(
                            consts.START_DATE
                        ),
                    )
                )
                raise GTIAlertsException(
                    "StartDate '{}' is not a valid date in yyyy-mm-dd format".format(
                        consts.START_DATE
                    )
                )
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
                "Unexpected error determining start date: {}".format(err)
            )
