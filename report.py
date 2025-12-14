class Report:
    def __init__(self,all_entries,suspicious_entries):
        self.all_entries= all_entries #it count all the log entries
        self.suspicious_entries=suspicious_entries 

    def short_report(self):
        total_lines=len(self.all_entries)
        ip_set={e.ip_address for e in self.all_entries if e.ip_address} #IPs across all logs
        suspicious_ip={e.ip_address for e in self.suspicious_entries if e.ip_address}
        print("Short Summary Report")
        print(f"Total log entries: {total_lines}")
        print(f"Unique IP addresses: {len(ip_set)}")
        print(f"Suspicious IP addresses counter: {len(suspicious_ip)}")
        print(f"Suspicious IPs: {', '.join(suspicious_ip)}")

        return {
            "total_log_entries": total_lines,
            "unique_ip_addresses": len(ip_set),
            "suspicious_ip_addresses_count": len(suspicious_ip),
            "suspicious_ips": list(suspicious_ip)
        }
        

    def detailed_report(self):
        print("Detailed Report")
        detailed_info = {}

        for entry in self.suspicious_entries:
            ip = entry.ip_address
            detailed_info[ip] = {
                    "application": entry.app,
                    "failure_messages": list(entry.messages),
                    "timestamps": list(entry.timestamp),
                    "failed_attempts": entry.counter,
                    "total_requests": entry.totalRequests,
                    "failure_rate": round(entry.get_failure_rate(), 2),
                    "reason": "high failure rate" if entry.get_failure_rate() > 0.5 else "Moderate activity"
                }
            print(f"IP Address: {ip}")
            print(f"Application: {entry.app}")
            print(f"Failure Messages: {', '.join(entry.messages)}")
            print(f"Timestamps: {', '.join(entry.timestamp)}")
            print(f"Failed Attempts: {entry.counter}")
            print(f"Total Requests: {entry.totalRequests}")
            print(f'Failure Rate: {round(entry.get_failure_rate(), 2)}')
            print("Reason: " + ("high failure rate" if entry.get_failure_rate() > 0.5 else "Moderate activity"))
            print("-" * 40)
        return detailed_info


    def save_report(self,file_path="detailed_report.txt"):
        reportlog=self.detailed_report()
        
        with open(file_path,"w") as f:
            for key,value in reportlog.items():
                f.write(f"IP Address: {key}\n")
                for k,v in value.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
        print(f"report saved to {file_path}")
            
                

      
        