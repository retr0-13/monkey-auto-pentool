import logging
import threading
from typing import Dict

from infection_monkey.credential_collectors.credentials.complex_credentials import (
    ComplexCredentials,
)
from infection_monkey.credential_collectors.credentials.credentials import Credentials
from infection_monkey.i_puppet import (
    ExploiterResultData,
    FingerprintData,
    IPuppet,
    PingScanData,
    PluginType,
    PortScanData,
    PortStatus,
    PostBreachData,
)

DOT_1 = "10.0.0.1"
DOT_2 = "10.0.0.2"
DOT_3 = "10.0.0.3"
DOT_4 = "10.0.0.4"

logger = logging.getLogger()


class MockPuppet(IPuppet):
    def load_plugin(self, plugin: object, plugin_type: PluginType) -> None:
        logger.debug(f"load_plugin({plugin}, {plugin_type})")

    def run_credential_collector(self, name: str) -> Dict:
        logger.debug(f"run_sys_info_collector({name})")
        # TODO: More collectors
        if name == "MimikatzCollector":
            return Credentials(
                type="Mimikatz", data=[{"ntlm": "abc1", "lm": "abc2", "name": "test"}]
            )
        if name == "ComplexCollector":
            return ComplexCredentials(
                type="Complex", data=[{"unserializable_value": "!@#$%#$%", "some_data": "data"}]
            )
        return {}

    def run_pba(self, name: str, options: Dict) -> PostBreachData:
        logger.debug(f"run_pba({name}, {options})")

        if name == "AccountDiscovery":
            return PostBreachData("pba command 1", ["pba result 1", True])
        else:
            return PostBreachData("pba command 2", ["pba result 2", False])

    def ping(self, host: str, timeout: float = 1) -> PingScanData:
        logger.debug(f"run_ping({host}, {timeout})")
        if host == DOT_1:
            return PingScanData(True, "windows")

        if host == DOT_2:
            return PingScanData(False, None)

        if host == DOT_3:
            return PingScanData(True, "linux")

        if host == DOT_4:
            return PingScanData(False, None)

        return PingScanData(False, None)

    def scan_tcp_port(self, host: str, port: int, timeout: int = 3) -> PortScanData:
        logger.debug(f"run_scan_tcp_port({host}, {port}, {timeout})")
        dot_1_results = {
            22: PortScanData(22, PortStatus.CLOSED, None, None),
            445: PortScanData(445, PortStatus.OPEN, "SMB BANNER", "tcp-445"),
            3389: PortScanData(3389, PortStatus.OPEN, "", "tcp-3389"),
        }
        dot_3_results = {
            22: PortScanData(22, PortStatus.OPEN, "SSH BANNER", "tcp-22"),
            443: PortScanData(443, PortStatus.OPEN, "HTTPS BANNER", "tcp-443"),
            3389: PortScanData(3389, PortStatus.CLOSED, "", None),
        }

        if host == DOT_1:
            return dot_1_results.get(port, _get_empty_results(port))

        if host == DOT_3:
            return dot_3_results.get(port, _get_empty_results(port))

        return _get_empty_results(port)

    def fingerprint(
        self,
        name: str,
        host: str,
        ping_scan_data: PingScanData,
        port_scan_data: Dict[int, PortScanData],
    ) -> FingerprintData:
        logger.debug(f"fingerprint({name}, {host})")
        empty_fingerprint_data = FingerprintData(None, None, {})

        dot_1_results = {
            "SMBFinger": FingerprintData(
                "windows", "vista", {"tcp-445": {"name": "smb_service_name"}}
            )
        }

        dot_3_results = {
            "SSHFinger": FingerprintData(
                "linux", "ubuntu", {"tcp-22": {"name": "SSH", "banner": "SSH BANNER"}}
            ),
            "HTTPFinger": FingerprintData(
                None,
                None,
                {
                    "tcp-80": {"name": "http", "data": ("SERVER_HEADERS", False)},
                    "tcp-443": {"name": "http", "data": ("SERVER_HEADERS_2", True)},
                },
            ),
        }

        if host == DOT_1:
            return dot_1_results.get(name, empty_fingerprint_data)

        if host == DOT_3:
            return dot_3_results.get(name, empty_fingerprint_data)

        return empty_fingerprint_data

    def exploit_host(
        self, name: str, host: str, options: Dict, interrupt: threading.Event
    ) -> ExploiterResultData:
        logger.debug(f"exploit_hosts({name}, {host}, {options})")
        attempts = [
            {
                "result": False,
                "user": "Administrator",
                "password": "",
                "lm_hash": "",
                "ntlm_hash": "",
                "ssh_key": host,
            },
            {
                "result": False,
                "user": "root",
                "password": "",
                "lm_hash": "",
                "ntlm_hash": "",
                "ssh_key": host,
            },
        ]
        info_powershell = {
            "display_name": "PowerShell",
            "started": "2021-11-25T15:57:06.307696",
            "finished": "2021-11-25T15:58:33.788238",
            "vulnerable_urls": [],
            "vulnerable_ports": [],
            "executed_cmds": [
                {
                    "cmd": "/tmp/monkey m0nk3y -s 10.10.10.10:5000 -d 1 >git s /dev/null 2>&1 &",
                    "powershell": True,
                }
            ],
        }
        info_ssh = {
            "display_name": "SSH",
            "started": "2021-11-25T15:57:06.307696",
            "finished": "2021-11-25T15:58:33.788238",
            "vulnerable_urls": [],
            "vulnerable_ports": [22],
            "executed_cmds": [],
        }
        successful_exploiters = {
            DOT_1: {
                "PowerShellExploiter": ExploiterResultData(True, info_powershell, attempts, None),
                "ZerologonExploiter": ExploiterResultData(False, {}, [], "Zerologon failed"),
                "SSHExploiter": ExploiterResultData(False, info_ssh, attempts, "Failed exploiting"),
            },
            DOT_3: {
                "PowerShellExploiter": ExploiterResultData(
                    False, info_powershell, attempts, "PowerShell Exploiter Failed"
                ),
                "SSHExploiter": ExploiterResultData(False, info_ssh, attempts, "Failed exploiting"),
                "ZerologonExploiter": ExploiterResultData(True, {}, [], None),
            },
        }

        try:
            return successful_exploiters[host][name]
        except KeyError:
            return ExploiterResultData(False, {}, [], f"{name} failed for host {host}")

    def run_payload(self, name: str, options: Dict, interrupt: threading.Event):
        logger.debug(f"run_payload({name}, {options})")

    def cleanup(self) -> None:
        print("Cleanup called!")
        pass


def _get_empty_results(port: int):
    return PortScanData(port, PortStatus.CLOSED, None, None)
