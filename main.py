from log_analyzer import LogAnalyzer
file_path = input("File path: ")

if not file_path:
    file_path = './logs/LogAnalyzer_Syslog.txt'

log_analyzer = LogAnalyzer()
log_analyzer.load_logs(file_path)

log_analyzer.find_suspicious_entries()


