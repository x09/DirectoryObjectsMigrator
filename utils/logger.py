"""
Migration logger
Handles logging to file and GUI callback
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable
from config import settings


class MigrationLogger:
    """
    Custom logger for migration operations
    Supports file logging and optional GUI callback for real-time display
    """

    def __init__(self, log_file: Optional[Path] = None, gui_callback: Optional[Callable] = None):
        """
        Initialize logger

        Args:
            log_file: Path to log file (if None, auto-generated in logs directory)
            gui_callback: Optional callback function for GUI updates
                         Signature: callback(level: str, message: str)
        """
        self.gui_callback = gui_callback
        self.current_phase = None

        # Create log file if not specified
        if log_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = settings.LOGS_DIR / f"migration_{timestamp}.log"

        self.log_file = log_file

        # Setup Python logging
        self.logger = logging.getLogger('MigrationLogger')
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        self.logger.handlers.clear()

        # File handler
        file_handler = logging.FileHandler(str(log_file), encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)-8s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '[%(levelname)-8s] %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        self.info(f"=== Migration Log Started ===")
        self.info(f"Log file: {log_file}")

    def set_log_level(self, level: str):
        """
        Set logging level

        Args:
            level: One of DEBUG, INFO, WARNING, ERROR
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }

        numeric_level = level_map.get(level.upper(), logging.INFO)

        # Update console handler level
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(numeric_level)

    def set_phase(self, phase_name: str):
        """
        Set current migration phase

        Args:
            phase_name: Phase name (e.g., "Analysis", "Creating OUs")
        """
        self.current_phase = phase_name
        self.info(f"=== Phase: {phase_name} ===")

    def _log(self, level: str, message: str, log_level: int):
        """
        Internal logging method

        Args:
            level: Level name for GUI (INFO, SUCCESS, WARNING, ERROR, CONFLICT)
            message: Log message
            log_level: Python logging level
        """
        # Format message with phase if set
        if self.current_phase and level not in ['DEBUG']:
            formatted_message = f"[{self.current_phase}] {message}"
        else:
            formatted_message = message

        # Log to file/console
        self.logger.log(log_level, formatted_message)

        # Call GUI callback if provided
        if self.gui_callback:
            try:
                self.gui_callback(level, formatted_message)
            except Exception as e:
                self.logger.error(f"GUI callback error: {e}")

    def debug(self, message: str):
        """Log debug message"""
        self._log('DEBUG', message, logging.DEBUG)

    def info(self, message: str):
        """Log info message"""
        self._log('INFO', message, logging.INFO)

    def success(self, message: str):
        """Log success message (INFO level with SUCCESS tag)"""
        self._log('SUCCESS', message, logging.INFO)

    def warning(self, message: str):
        """Log warning message"""
        self._log('WARNING', message, logging.WARNING)

    def error(self, message: str):
        """Log error message"""
        self._log('ERROR', message, logging.ERROR)

    def critical(self, message: str):
        """Log critical error message"""
        self._log('CRITICAL', message, logging.CRITICAL)

    def conflict(self, message: str):
        """Log conflict message (WARNING level with CONFLICT tag)"""
        self._log('CONFLICT', message, logging.WARNING)

    def separator(self):
        """Log a separator line"""
        self.info("-" * 80)

    def close(self):
        """Close logger and flush handlers"""
        self.info("=== Migration Log Ended ===")
        for handler in self.logger.handlers:
            handler.flush()
            handler.close()


class LoggerContext:
    """Context manager for logger with automatic cleanup"""

    def __init__(self, log_file: Optional[Path] = None, gui_callback: Optional[Callable] = None):
        self.log_file = log_file
        self.gui_callback = gui_callback
        self.logger = None

    def __enter__(self) -> MigrationLogger:
        self.logger = MigrationLogger(self.log_file, self.gui_callback)
        return self.logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.logger:
            if exc_type:
                self.logger.error(f"Exception occurred: {exc_val}")
            self.logger.close()


if __name__ == "__main__":
    # Self-test
    def gui_callback(level, message):
        print(f"[GUI] {level}: {message}")

    with LoggerContext(gui_callback=gui_callback) as logger:
        logger.info("Starting test")
        logger.set_phase("Test Phase")
        logger.debug("Debug message")
        logger.info("Info message")
        logger.success("Success message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.conflict("Conflict message")
        logger.separator()
        logger.info("Test complete")

    print(f"\nLog file created at: {settings.LOGS_DIR}")
