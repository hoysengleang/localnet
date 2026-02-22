from enum import Enum


class PolicyAcl(Enum):
    ALLOW_ALL = "allow_all"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
