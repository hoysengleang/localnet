from enum import Enum


class ScannerPolicyEnum(Enum):
    DISCOVERY_PORT  = 54321
    DISCOVERY_MAGIC = "LOCALNET-CONTROL-BEACON-V1"
    BROADCAST_ADDR  = "255.255.255.255"
    SCAN_TIMEOUT    = 2.0
