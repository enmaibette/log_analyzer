from log_analyzer import LogAnalyzer
from report import Report

def check_file_path(file_path):
    try:
        with open(file_path, 'r') as f:
            return True
    except FileNotFoundError:
        print(f"File not found: {file_path}. Please enter a valid file path.")
        return False
    

def show_menu():
    print("\n")
    print("-"*40)
    print("\n")
    user_options = None
    while user_options is None:
        print("1. View all log entries")
        print("2. Save all log entries as JSON")
        print("3. View suspicious log entries")
        print("4. Short summary report")
        print("5. Detailed report")
        print("6. Exit")
        try:
            user_options = int(input("Write the number of your choice: "))
            if user_options < 1 or user_options > 6:
                print("Input not recognized, please try again.")
                user_options = None
        except ValueError:
            print("Input not recognized, please try again.")
    
    print("\n")
    print("-"*40)
    print("\n")
    return user_options


log_analyzer = None
suspicious_after = None
file_path = None


while not log_analyzer:
    file_path = input("File path (default is ./logs/LogAnalyzer_Syslog.txt): ") if file_path is None else file_path
    
    if not file_path:
        file_path = './logs/LogAnalyzer_Syslog.txt'
    
    file_exists = check_file_path(file_path)
    if not file_exists:
        file_path = None
        continue

    suspicious_after = input("Number of failed attempts to consider an IP suspicious (default is 5): ") if suspicious_after is None else suspicious_after

    if not suspicious_after:
        suspicious_after = 5
    
    try:
        suspicious_after = int(suspicious_after)
    except ValueError:
        suspicious_after = None
        print("Please enter a valid integer for suspicious attempts.")
        continue

    
    log_analyzer = LogAnalyzer(file_path=file_path, suspicious_after=suspicious_after)

report = Report(log_analyzer.entries,  log_analyzer.suspicious_entries)

while(True):
    user_options = show_menu()

    match user_options:
        case 1:
            log_analyzer.display_all_entries()
        case 2:

            log_analyzer.save_log_as_json()
        case 3:
            log_analyzer.display_suspicious_entries()
        case 4:
            report.short_report()
        case 5:
            report.detailed_report()
            if input("Would you like to save the report? (y/n): ").lower() == 'y':
                report.save_report()
            else:
                print("Report not saved.")
        case 6:
            print("Exiting the program. Goodbye!")
            break
        case default:
            print("Input not recognized, please try again.")