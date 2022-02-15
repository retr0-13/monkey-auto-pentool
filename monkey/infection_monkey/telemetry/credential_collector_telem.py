from twisted.cred.credentials import ICredentials

from common.common_consts.telem_categories import TelemCategoryEnum
from infection_monkey.telemetry.base_telem import BaseTelem


class CredentialCollectorTelem(BaseTelem):
    def __init__(self, credentials: ICredentials):
        """
        Default system info telemetry constructor
        :param system_info: System info returned from SystemInfoCollector.get_info()
        """
        self.credentials = credentials

    telem_category = TelemCategoryEnum.SYSTEM_INFO

    def get_data(self):
        return self.telem_category

    def send(self, log_data=False):
        super().send(self.credentials)
