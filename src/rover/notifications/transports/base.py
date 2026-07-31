"""src/rover/notifications/transports/base.py — Abstract Base Class for Notification Transports."""

from abc import ABC, abstractmethod
from typing import Any


class BaseTransport(ABC):
    """Abstract base class for all pluggable notification transport adapters."""

    @abstractmethod
    def deliver(
        self,
        destination: dict[str, Any],
        payload: dict[str, Any],
        vault_secret: dict[str, Any] | None = None,
    ) -> bool:
        """Delivers a notification payload to the given destination.

        Args:
            destination: Destination record containing config_json and metadata.
            payload: Notification payload event dictionary.
            vault_secret: Decrypted secret dictionary from OpenBao Vault.

        Returns:
            bool: True if delivery succeeded, False otherwise.
        """
        pass
