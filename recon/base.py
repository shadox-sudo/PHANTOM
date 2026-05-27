"""
PHANTOM — Base Recon Module

All reconnaissance modules inherit from ReconModule ABC.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class ReconModule(ABC):
    """Base class for all reconnaissance modules.
    
    Class attributes to override:
        name: Unique module identifier.
        description: Human-readable description.
        depends_on: List of other recon module names required before this one.
    """

    name: str = "base_recon"
    description: str = "Base recon module"
    depends_on: list[str] = []

    @abstractmethod
    def run(self, target, config=None):
        """Execute the recon module against the target.
        
        Args:
            target: Target object to read from and write to.
            config: Optional Settings object.
        
        Returns:
            Updated Target object.
        
        Raises:
            ReconError: On fatal failure.
        """
        ...

    def validate_target(self, target) -> bool:
        """Check if target has enough data for this module to run.
        
        Override in subclasses for custom validation.
        
        Args:
            target: Target object.
        
        Returns:
            True if target is valid for this module.
        """
        return target is not None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
