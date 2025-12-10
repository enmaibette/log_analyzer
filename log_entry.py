class LogEntry:
    def __init__(self, timestamp, hostname, applicationName, ipAddress, message, failed):
        self.timestamp = timestamp
        self.hostname = hostname
        self.applicationName = applicationName
        self.ipAddress = ipAddress
        self.message = message
        self.failed = failed
