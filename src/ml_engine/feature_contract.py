"""Shared ML feature contract for NoEsc train-serve parity."""

FEATURE_CONTRACT_VERSION = "v2_syscall_user_auth_context"

EVENT_TYPES_INCLUDED = ("SYSCALL", "USER_AUTH")
EVENT_TYPES_INCLUDED_SET = set(EVENT_TYPES_INCLUDED)

PAYLOAD_FIELDS = (
    "type",
    "syscall",
    "res",
    "auid",
    "euid",
    "exe",
    "pid",
    "timestamp",
)

# Order is part of the contract and must stay stable across training and runtime.
CONTEXT_FEATURE_COLUMNS = (
    "ctx_euid_is_root",
    "ctx_auid_non_zero",
    "ctx_auid_euid_mismatch",
    "ctx_exe_in_tmp",
    "ctx_exe_in_usr_bin",
    "ctx_auth_total_count",
    "ctx_auth_failed_count",
    "ctx_auth_failure_rate",
)
