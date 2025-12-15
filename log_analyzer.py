import json
from suspicious_entry import SuspiciousEntry
from log_entry import LogEntry

import re
SERVICES = ['auth', 'web', 'fw', 'app']
SERVICES_PATTERN = "|".join(SERVICES)
class LogAnalyzer:
    def __init__(self, file_path='./logs/LogAnalyzer_Syslog.txt',suspicious_after=5):
        self.entries: list[LogEntry] = self.load_logs(file_path) or []
        self.suspicious_after = suspicious_after
        self.suspicious_entries = self.find_suspicious_entries()
    
    def load_logs(self, file_path):
        file = open(file_path, 'r')
        log_entries = []
        for line in file:
            timestamp = self.extract_timestamp(line)
            hostname = self.extract_hostname(line)
            application_name = self.extract_application_name(line)
            ip_address = self.extract_ip_address(line)
            message = self.extract_message(line)
            failed = self.ip_failed(line)
            failed_message = self.analyze_logs(line)
            log_entry = LogEntry(timestamp, hostname, application_name, ip_address, message, failed, failed_message)
            log_entries.append(log_entry)
        return log_entries

    def display_all_entries(self):
        for entry in self.entries:
            print(f'Timestamp: {entry.timestamp} | IP Address: {entry.ip_address} | Hostname: {entry.hostname} | Application: {entry.application_name} | Message: {entry.message} | Failed: {entry.failed} | Failed Message: {entry.failed_message}')

    def extract_timestamp(self, log_line: str):
        timestamp = re.split(rf'\s({SERVICES_PATTERN})\d+', log_line)[0]
        return timestamp

    def extract_hostname(self, log_line):
        hostname = re.search(rf'({SERVICES_PATTERN})\d+', log_line).group()
        return hostname if hostname else ''

    def extract_application_name(self, log_line):
        # search for first match of the pattern
        app_name = re.search(rf'(\w+)\[\d+\]\:|([a-zA-Z]+)\:', log_line)
        return app_name.group() if app_name else ''

    def extract_ip_address(self, log_line):
        # \b -> wourd boundary
        # (?:...) -> non-capturing group
        ip_list = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        ip = ''
        if len(ip_list) > 1:
            log_line_parts = log_line.split(ip_list[0])
            if 'SRC' in log_line_parts[0]:
                ip = ip_list[0]
            elif 'SRC' in log_line_parts[1]:
                ip = ip_list[1]
            else:
                print("Cannot determine source IP in line:", log_line)
        else:
            ip = ip_list[0] if ip_list else ''
        return ip

    def ip_failed(self, log_line):
        failed_pattern = ['Failed password', 'DENIED', 'ERROR']
        status_codes = ['401', '403', '404', '500', '502', '503', '504']
        http_pattern = re.search(r'(HTTP\/((\d\.\d)|(\d))\")\s\w+', log_line)
        for pattern in failed_pattern:
            if pattern in log_line:
                return True
            if http_pattern != None:
                http_status = re.split(' ', http_pattern.group())[-1].strip()
                if http_status in status_codes:
                    return True
        return False

    def extract_message(self, log_line):
        # :? non-capturing group -> we don't need to capture this part which is the application name 
        # we want to split by it and get the message after it
        message = re.split(r'(?:\w+)\[\d+\]\:|(?:[a-zA-Z]+)\:', log_line, maxsplit=1)[-1].strip()
        return message

    def analyze_logs(self, log_line):
        failed_pattern = ['Failed password', 'DENIED', 'ERROR']
        status_codes = ['401', '403', '404', '500', '502', '503', '504']
        http_pattern = re.search(r'(HTTP\/((\d\.\d)|(\d))\")\s\w+', log_line)
        for pattern in failed_pattern:
            if pattern in log_line:
                return pattern
            if http_pattern != None:
                http_status = re.split(' ', http_pattern.group())[-1].strip()
                if http_status in status_codes:
                    return http_status
        return None

    def find_suspicious_entries(self):
        count_failed_entries = {}
        suspicious_entries = []
        for entry in self.entries:
            if count_failed_entries.get(entry.ip_address) is None:
                    count_failed_entries[entry.ip_address] = SuspiciousEntry(entry.ip_address, entry.application_name)
            if entry.failed:
                count_failed_entries[entry.ip_address].increment_counter()
                count_failed_entries[entry.ip_address].add_message(entry.failed_message)
                count_failed_entries[entry.ip_address].add_timestamp(entry.timestamp)

            count_failed_entries[entry.ip_address].increment_total_requests()

        for (_, val) in count_failed_entries.items():
            if val.counter >= self.suspicious_after:
                suspicious_entries.append(val)
        return suspicious_entries
    
    def display_suspicious_entries(self):
        for entry in self.suspicious_entries:
            print(f'IP Address: {entry.ip_address} | Failed Attempts: {entry.counter} | Failure Messages: {", ".join(entry.messages)}')

    def save_log_as_json(self):
        file_path = None
        while not file_path:
            file_path = input("Enter the file path to save the log entires as JSON (default: './logs/logs.json'): ")
            if not file_path:
                file_path = './logs/logs.json'
            try: 
                open(file_path, "w").close()
            except FileNotFoundError:
                print("Directory does not exist. Please enter a valid file path.")
                file_path = None

        with open(file_path,"w") as f:
             # indent -> controls pretty printing of the JSON file. Indent=4 means each level is indented by 4 spaces
            json.dump(self.entries, f, default=lambda o: o.__dict__, indent=4)
        print(f"report saved to {file_path}")
