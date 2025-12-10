from log_entry import LogEntry

import re
SERVICES = ['auth', 'web', 'fw', 'app']
SERVICES_PATTERN = "|".join(SERVICES)
class LogAnalyzer:
    def __init__(self):
        self.entries: list[LogEntry] = []
    
    def load_logs(self, file_path='./logs/LogAnalyzer_Syslog.txt'):
        file = open(file_path, 'r')
        for line in file:
            timestamp = self.extract_timestamp(line)
            hostname = self.extract_hostname(line)
            applicationName = ''
            ipAddress = self.extract_ip_address(line)
            message = ''
            log_entry = LogEntry(timestamp, hostname, applicationName, ipAddress, message)
            self.entries.append(log_entry)
        pass

    def extract_timestamp(self, log_line: str):
        timestamp = re.split(rf'\s({SERVICES_PATTERN})\d+', log_line)[0]
        return timestamp

    def extract_hostname(self, log_line):
        hostname = re.search(rf'({SERVICES_PATTERN})\d+', log_line).group()
        print(hostname)
        return hostname if hostname else ''


        pass

    def extract_application_name(self, log_line):
        app_name = re.search(rf'(\w+)\[\d+\]'l,log_line)
        return app_name.group() if app_name else ''
        
        pass

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

    def extract_message(self, log_line):
        pass

    def analyze_logs(self):
        pass

    def find_suspicious_entries(self):
        pass

    def save_as_json(self, file_path):
        pass
