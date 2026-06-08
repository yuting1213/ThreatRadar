import os
import logging
from logging.handlers import RotatingFileHandler

# Configuration Constants
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'app.log')
MAX_BYTES = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 3


def setup_logger(name: str) -> logging.Logger:
    """
    Configures and returns a logger instance with rotating file and console handlers.

    Args:
        name (str): The name of the logger module (typically __name__).

    Returns:
        logging.Logger: The configured logger instance.
    """
    # Ensure the log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if the logger is called multiple times
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # File handler with log rotation
        file_handler = RotatingFileHandler(
            filename=LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)

        # Stream handler for console output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
