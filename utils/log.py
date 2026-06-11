"""PHANTOM — Logging Setup"""
import logging
import sys
from typing import Optional


# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_MAGENTA = "\033[95m"
_CYAN = "\033[96m"
_WHITE = "\033[97m"


class _ColoredFormatter(logging.Formatter):
    """Custom formatter with ANSI color output."""

    LEVEL_COLORS = {
        logging.DEBUG: _DIM + _WHITE,
        logging.INFO: _GREEN,
        logging.WARNING: _YELLOW + _BOLD,
        logging.ERROR: _RED + _BOLD,
        logging.CRITICAL: _RED + _BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        level_color = self.LEVEL_COLORS.get(record.levelno, _WHITE)
        
        # Format: [HH:MM:SS] LEVEL  module: message
        timestamp = f"{self.formatTime(record, '%H:%M:%S')}"
        
        level_name = f"{record.levelname:<5}"
        colored_level = f"{level_color}{level_name}{_RESET}"
        
        module_name = f"{_CYAN}{record.name}{_RESET}"
        
        return f"[{timestamp}] {colored_level} {module_name}: {record.getMessage()}"


def setup_logger(level: str = "INFO",
                 log_file: Optional[str] = None,
                 quiet: bool = False) -> logging.Logger:
    """Configure root logger with colored console output.
    
    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
        log_file: Optional path to log file.
        quiet: If True, suppress console output.
    
    Returns:
        Configured root logger.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logger = logging.getLogger("phantom")
    logger.setLevel(numeric_level)
    logger.handlers.clear()
    
    if not quiet:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(numeric_level)
        console.setFormatter(_ColoredFormatter())
        logger.addHandler(console)
    
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        logger.addHandler(fh)
    
    return logger
