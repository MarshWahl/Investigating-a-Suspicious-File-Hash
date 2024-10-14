# Investigating-a-Suspicious-File-Hash

In this project, I will analyze an artifact using VirusTotal and capture details about its related indicators of compromise using the Pyramid of Pain.

## Scenario
You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 
You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 
You retrieve the malicious file and create a SHA256 hash of the file: SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:
1:11 p.m.: An employee receives an email containing a file attachment.
1:13 p.m.: The employee successfully downloads and opens the file.
1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.
1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.

Utilizing [[VirusTotal](https://www.virustotal.com/gui/home/upload)] to investigate the SHA256 file hash, we are given a wealth of information.

![image](https://github.com/user-attachments/assets/66fa0144-bf99-49d8-b72a-a136f9ad8b79)
The information found under the Detection tab, the Community Score, and the Security vendors' analysis listed in the VirusTotal report provide insight into the file. Over fifty security vendors have flagged this file as malicious. Additionally, multiple vendors have categorized the file as Flagpro malware, a well-known malware used by advanced threat actors.

The following diagram shows the Flagpro malware broken down in the Pyramid of Pain, collected from information within the **Details**, **Relation**, and **Behaviour** tabs on VirusTotal:
![image](https://github.com/user-attachments/assets/237bf48b-7c02-47ef-a8b5-137fe6834370)

- **Domain names**: org.misecure. com is reported as a malicious contacted domain under the Relations tab in the VirusTotal report.
- **IP address**: 207.148.109.242 is listed as one of many IP addresses under the Relations tab in the VirusTotal report. This IP address is also associated with the org.misecure.com domain as listed in the DNS Resolutions section under the Behavior tab from the Zenbox sandbox report.
- **Hash value**: 287d612e29b71c90aa54947313810a25 is a MD5 hash listed under the Details tab in the VirusTotal report.
- **Network/host artifacts**: Network-related artifacts that have been observed in this malware are HTTP requests made to the org.misecure.com domain. This is listed in the Network Communications section under the Behavior tab from the Venus Eye Sandbox and Rising MOVES sandbox reports.
- **Tools**: Input capture is listed in the Collection section under the Behavior tab from the Zenbox sandbox report. Malicious actors use input capture to steal user input such as passwords, credit card numbers, and other sensitive information.
**TTPs**: Command and control is listed as a tactic under the Behavior tab from the Zenbox sandbox report. Malicious actors use command and control to establish communication channels between an infected system and their own system.
