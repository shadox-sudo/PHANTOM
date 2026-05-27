"""
PHANTOM — Base Vulnerability Check Module

All vulnerability checks inherit from VulnCheck ABC.
"""
from __future__ import annotations
from abc import ABC, abstractmethod


class VulnCheck(ABC):
    """Base class for all vulnerability detection checks.
    
    Class attributes to override:
        name: Unique identifier.
        description: Human-readable description.
        severity: Default severity level.
        requires: List of data requirements (e.g., ['endpoints', 'open_ports']).
    """

    name: str = "base_vuln"
    description: str = "Base vulnerability check"
    severity: str = "medium"
    requires: list[str] = []

    @abstractmethod
    def check(self, target, config=None) -> list:
        """Run vulnerability check against target.
        
        Args:
            target: Target object with recon data.
            config: Optional Settings object.
        
        Returns:
            List of VulnerabilityFinding objects.
        """
        ...

    def validate_target(self, target) -> bool:
        """Check if target has required data for this check.
        
        Checks if all items in self.requires exist on the target.
        
        Args:
            target: Target object.
        
        Returns:
            True if target has all required data.
        """
        for req in self.requires:
            if not hasattr(target, req):
                return False
            data = getattr(target, req)
            if not data:
                return False
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name} ({self.severity})>"
