from log_analyzer import LogAnalyzer
from report import Report
log_analyzer = None
suspicious_after = None

while not log_analyzer:
    file_path = input("File path (default is ./logs/LogAnalyzer_Syslog.txt): ")
    suspicious_after = input("Number of failed attempts to consider an IP suspicious (default is 5): ") if suspicious_after is None else suspicious_after
    if not file_path:
        file_path = './logs/LogAnalyzer_Syslog.txt'

    if not suspicious_after:
        suspicious_after = 5
    try:
        log_analyzer = LogAnalyzer(file_path=file_path, suspicious_after=int(suspicious_after))
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")

report = Report(log_analyzer.entries,  log_analyzer.suspicious_entries)


user_options = ''
print("\n")
print("-"*40)
print("\n")
while(user_options != '6'):

    print("1. View all log entries")
    print("2. Save all log entries as JSON")
    print("3. View suspicious log entries")
    print("4. Short summary report")
    print("5. Detailed report")
    print("6. Exit")
    user_options = input("Write the number of your choice:")
    print("\n")
    print("-"*40)
    print("\n")

    match user_options:
        case '1':
            log_analyzer.display_all_entries()
        case '2':
            path = input("Enter the file path to save the log entires as JSON (default: './logs/logs.json'): ")
            if not path:
                path = './logs/logs.json'
            log_analyzer.save_log_as_json(file_path=path)
        case '3':
            log_analyzer.display_suspicious_entries()
        case '4':
            report.short_report()
        case '5':
            report.detailed_report()
            if input("Would you like to save the report? (y/n): ").lower() == 'y':
                path_to_save = input("Enter the file path to save the report (default: 'save_report.txt'): ")
                if not path_to_save:
                    path_to_save = "save_report.txt"
                report.save_report(path_to_save)
            else:
                print("Report not saved.")
        case '6':
            print("Exiting the program.")
            exit()

    print("\n")
    print("-"*40)
    print("\n")