from log_entry import LogEntry

import re
SERVICES = ['auth', 'web', 'fw', 'app']
SERVICES_PATTERN = "|".join(SERVICES)
class LogAnalyzer:
    def __init__(self, suspicious_after=5):
        self.entries: list[LogEntry] = []
        self.suspicious_after = suspicious_after
    
    def load_logs(self, file_path):
        file = open(file_path, 'r')
        for line in file:
            timestamp = self.extract_timestamp(line)
            hostname = self.extract_hostname(line)
            applicationName = self.extract_application_name(line)
            ipAddress = self.extract_ip_address(line)
            message = self.extract_message(line)
            failed = self.ip_failed(line)
            log_entry = LogEntry(timestamp, hostname, applicationName, ipAddress, message, failed)
            self.entries.append(log_entry)
            print(line)

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

    def analyze_logs(self):
        pass

    def find_suspicious_entries(self):
        count_failed_entries = {}
        suspicious_entries = {}
        for entry in self.entries:
            if count_failed_entries.get(entry.ipAddress) is None:
                count_failed_entries[entry.ipAddress] = 0
            if entry.failed:
                count_failed_entries[entry.ipAddress] += 1

        for (ip, count) in count_failed_entries.items():
            if count >= self.suspicious_after:
                suspicious_entries[ip] = count

        print("Suspicious entries:", suspicious_entries)
        return suspicious_entries

    def save_as_json(self, file_path):
        pass
