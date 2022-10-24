# Import required packages.
import logging
import logging.config
import utils.logging_handlers
import time
import os
import rich
import yaml

from interface import main_window

# Define constants.
LOGGING_LEVEL = "INFO"  # Choices are: "DEBUG", "INFO", "WARN", "CRITICAL", "ERROR"

def setup_logger(level) -> logging.Logger:
    """
    Sets up the built-in python logger with the appropriate handlers and formatting.

    Parameters:
    -----------
        level - The level/depth at which information is logged.

    Returns:
    --------
        Logger - The logger object to interface with.
    """
    # Create log output directory.
    os.makedirs("logs", exist_ok=True)

    # Load config file.
    log_config = yaml.safe_load(open("logging_config.yaml", "r", encoding="utf-8").read())
    logging.config.dictConfig(log_config)

    # Loop through the configured handlers in the yaml file and set their level.
    for handler in logging.getLogger().handlers:
        # Check if handler is an actual text console one.
        if isinstance(handler, type(rich.logging.RichHandler())):
            handler.setLevel(level)

    return logging.getLogger()

def main() -> None:
    """
    Main program method.
    """
    try:
        # Initialize logger.
        logger = setup_logger(LOGGING_LEVEL)

        # Start UI.
        interface = main_window.MainUI()
        interface.initialize_window()

        # Main loop that runs as long as the main window is open.
        while interface.get_is_window_open():
            # Update window.
            interface.update_window()
            # Sleep
            time.sleep(1/120)
    except Exception as exception:
        logger.critical("MAIN THREAD CRASH:", exc_info=exception, stack_info=True)

if __name__ == "__main__":
    # Call main function.
    main()
