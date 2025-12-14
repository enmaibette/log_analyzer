class LogEntry:
    def __init__(self, timestamp, hostname, application_name, ip_address, message, failed, failed_message=None):
        self.timestamp = timestamp
        self.hostname = hostname
        self.application_name = application_name
        self.ip_address = ip_address
        self.message = message
        self.failed = failed
        self.failed_message = failed_message
