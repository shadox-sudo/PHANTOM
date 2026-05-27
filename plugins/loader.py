"""
PHANTOM — Plugin Loader

Discovers and loads modules from plugin directories.
Supports ReconModule, VulnCheck, and ExploitModule types.
"""
from __future__ import annotations
import importlib
import importlib.util
import logging
import os
import sys
from typing import Any

from recon.base import ReconModule
from vuln.base import VulnCheck
from exploit.base import ExploitModule

logger = logging.getLogger("phantom.plugins")


class PluginLoader:
    """Discovers and loads plugin modules from the filesystem."""

    VALID_BASES = (ReconModule, VulnCheck, ExploitModule)

    def __init__(self) -> None:
        self.loaded_modules: dict[str, Any] = {}

    def discover(self, directory: str) -> list[str]:
        """Find all Python files in a directory (excluding __init__).
        
        Args:
            directory: Path to search for plugin files.
        
        Returns:
            List of absolute .py file paths.
        """
        plugin_files: list[str] = []
        
        if not os.path.isdir(directory):
            logger.warning("Plugin directory not found: %s", directory)
            return plugin_files
        
        for filename in sorted(os.listdir(directory)):
            if filename.startswith("_") or filename.startswith("."):
                continue
            if filename.endswith(".py"):
                plugin_files.append(os.path.join(directory, filename))
        
        return plugin_files

    def load(self, module_path: str) -> Any:
        """Load a single plugin file and return its module class instances.
        
        Args:
            module_path: Path to .py file.
        
        Returns:
            List of instantiated module objects (ReconModule, VulnCheck, ExploitModule).
        
        Raises:
            PluginValidationError: If module is invalid.
        """
        from core.exceptions import PluginValidationError
        
        # Derive module name from filename
        module_name = os.path.splitext(os.path.basename(module_path))[0]
        
        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if not spec or not spec.loader:
            raise PluginValidationError(f"Cannot load spec for {module_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Find plugin classes in the module
        instances = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if not isinstance(attr, type):
                continue
            if attr is ReconModule or attr is VulnCheck or attr is ExploitModule:
                continue
            if issubclass(attr, self.VALID_BASES):
                try:
                    instance = attr()
                    instances.append(instance)
                    logger.info("Loaded plugin: %s from %s", instance.name, module_name)
                except Exception as e:
                    logger.warning("Failed to instantiate %s: %s", attr_name, e)
        
        return instances

    def load_all(self, directory: str) -> list:
        """Load all plugins from a directory.
        
        Args:
            directory: Path to plugin directory.
        
        Returns:
            List of all loaded module instances.
        """
        all_instances: list = []
        plugin_files = self.discover(directory)
        
        for path in plugin_files:
            try:
                instances = self.load(path)
                all_instances.extend(instances)
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", path, e)
        
        logger.info("Loaded %d plugins from %s", len(all_instances), directory)
        return all_instances

    def validate_module(self, module: Any) -> bool:
        """Check if a module is a valid PHANTOM plugin.
        
        Args:
            module: Object to validate.
        
        Returns:
            True if module is a valid ReconModule, VulnCheck, or ExploitModule.
        """
        return isinstance(module, self.VALID_BASES)
