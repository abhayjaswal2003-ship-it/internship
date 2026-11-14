import logging
from config import LOG_FILE
from database.db_manager import db_manager

# Configure file logging
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("NetScope")

def log_event(level: str, source: str, message: str):
    """Log to file logging engine and persistent SQLite database."""
    log_msg = f"[{source}] {message}"
    if level.upper() == "INFO":
        logger.info(log_msg)
    elif level.upper() == "WARNING":
        logger.warning(log_msg)
    elif level.upper() == "ERROR":
        logger.error(log_msg)
    else:
        logger.debug(log_msg)

    try:
        db_manager.add_log(level.upper(), source, message)
    except Exception as e:
        print(f"Error logging to DB: {e}")
