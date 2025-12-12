import json
class Report:
    def __init__(self,all_entries,suspicious_entries):
        self.all_entries= all_entries #it count all the log entries
        self.suspicious_entries=suspicious_entries 

    def short_report(self):
        total_lines=len(self.all_entries)
        ip_set={e.ipAddress for e in self.all_entries if e.ipAddress} #IPs across all logs
        ip_set={e.ipAddress for e in self.all_entries if e.ipAddress} 
        suspicious_ip={e.ipAddress for e in self.suspicious_entries if e.ipAddress}
        
        return {
            "total_lines":total_lines,
            "unique_ip_count":len(ip_set),
            "suspicious_ip_count":len(suspicious_ip),
            "suspicious_ip":list(suspicious_ip),

         }
    
                


        

    def detailed_report(self):
        ip_stats={}
        for e in self.suspicious_entries:
            ip=e.ipAddress
            if not ip:
                continue
            if ip not in ip_stats:
                ip_stats[ip]={"failure":0,
                              "total":0,
                              "app":{},
                              "failedMessage":set()
                              }
            ip_stats[ip]["total"]+=1
            if e.failed:
                ip_stats[ip]["failure"]+=1
                ip_stats[ip]["failedMessage"].add(e.message)
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
    def save_report(self,file_patch="save_report.json"):
        reportlog={
            "short_report":self.short_report(),
            "detailed_report":self.detailed_report()
        }
        with open(file_patch,"w") as f:
            json.dump(reportlog,f,indent=4)
        print(f"report saved to {file_patch}")
            
                

      
        