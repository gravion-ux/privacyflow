"""Privacyflow safe VPN profile tooling.

Public API
----------
``load_config``                 parse and validate a Privacyflow configuration
``validate_wireguard_profile``  validate a single WireGuard profile
``rotation_plan``               build the dry-run rotation plan
"""
from .config import (
    ConfigError,
    PrivacyflowConfig,
    load_config,
    rotation_plan,
    validate_wireguard_profile,
)

__all__ = [
    "ConfigError",
    "PrivacyflowConfig",
    "__version__",
    "load_config",
    "rotation_plan",
    "validate_wireguard_profile",
]

__version__ = "0.1.0"
