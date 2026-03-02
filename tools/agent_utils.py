import logging

# Configuring the logging settings
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class AgentError(Exception):
    """Base class for exceptions raised by agent nodes."""
    pass

class AgentLogger:
    """Logger utility for agent nodes."""

    def __init__(self, name):
        self.logger = logging.getLogger(name)

    def log_info(self, message):
        self.logger.info(message)

    def log_warning(self, message):
        self.logger.warning(message)

    def log_error(self, message):
        self.logger.error(message)
        raise AgentError(message)

    def log_exception(self, exception):
        self.logger.exception(exception)
        raise AgentError(str(exception))

# Example Usage:
# agent_logger = AgentLogger('AgentNode1')
# agent_logger.log_info('This is an information log.');
# agent_logger.log_error('This is an error message.');
