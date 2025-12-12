class Report:
    def __init__(self, suspicious_entries):
        self.suspicious_entries = suspicious_entries

    def short_report(self):
        total_lines=len(self.suspicious_entries)
        ip_lines = sum(1 for e in self.suspicious_entries if e.ipAddress)
        failures = sum(1 for e in self.suspicious_entries if e.failed)
        suspicious_ip=list({e.ipAddress for e in self.suspicious_entries if e.ipAddress})
        
        return {
            "total_lines":total_lines,
            "ip_lines":ip_lines,
            "suspicious_ip_count":len(suspicious_ip),
            "suspicious_ip":suspicious_ip,
            
        }
    
                


        

    def detailed_report(self):
        ip_stats={}
        for e in self.suspicious_entries:
            ip=e.ipAddress
            if not ip:
                continue
            if ip not in ip_stats:
                ip_stats[ip]={"failure":0,"total":0,"app":{}}
            ip_stats[ip]["total"]+=1
            if e.failed:
                ip_stats[ip]["failure"]+=1
                app=e.applicationName
                ip_stats[ip]["application"][app]=ip_stats[ip]["application"].get(app,0)+1
        report ={}
        for ip, stats in ip_stats.items():
            failure_rate=stats["failure"]/stats["total"] if stats["total"] else 0
            report[ip]={
                "failure":stats["failure"],
                "total_request":stats["total"],
                "failure_rate":round(failure_rate,2),
                "application":stats["application"],
                "reason":"high failure rate" if failure_rate>0.5 else "Moderate activity"
             }
            return report
            
                

        #suspicious IPs
        # their statistics (number of failures / total requests)
        # a short explanation of why they are suspicious (e.g. more than x
        # failures)
        # Other statistics are optional but can improve the grade, f.eg:
        # Failure per-application
        # Extra information about the failure
        # Number of failures by suspicious IP
        # Etc.
        