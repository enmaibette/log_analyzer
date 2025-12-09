class Report:
    def __init__(self, suspicious_entries):
        self.suspicious_entries = suspicious_entries

    def short_report(self):
        #total lines processed
        # number of lines that contain an IP address
        # total number of failure events
        # number of suspicious IPs and a list of them
        pass

    def detailed_report(self):
        #suspicious IPs
        # their statistics (number of failures / total requests)
        # a short explanation of why they are suspicious (e.g. more than x
        # failures)
        # Other statistics are optional but can improve the grade, f.eg:
        # Failure per-application
        # Extra information about the failure
        # Number of failures by suspicious IP
        # Etc.
        pass