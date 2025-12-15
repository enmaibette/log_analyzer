class SuspiciousEntry:
    def __init__(self, ip_address, app, ):
        self.ip_address = ip_address
        self.app = app
        self.counter = 0
        self.total_requests = 0
        self.messages = set()
        self.timestamp = set()

    def increment_counter(self):
        self.counter += 1

    def increment_total_requests(self):
        self.total_requests += 1
    
    def get_failure_rate(self):
        return self.counter / self.total_requests if self.total_requests else 0
    
    def add_message(self, message):
        self.messages.add(message)

    def add_timestamp(self, timestamp):
        self.timestamp.add(timestamp)