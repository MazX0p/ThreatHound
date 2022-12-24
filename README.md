# ThreatHound

# I’ve built the following:
- A dedicated backend to support Sigma rules for python
- A dedicated backend for parsing evtx for python 
- A dedicated backend to match between evtx and the Sigma rules

# Features of the tool:
- Automation for Threat hunting, Compromise Assessment, and Incident Response for the Windows Event Logs
- Downloading and updating the Sigma rules daily from the source
- More then 50 detection rules included
- support for more then 1500 detection rules for Sigma
- Support for new sigma rules dynamically and adding it to the detection rules
- Saving of all the outputs in JSON format
- Easily add any detection rules you prefer 
- you can add new event log source type in mapping.py easily 

# To-do:
- Support for Sigma rules dedicated for DNS query 
- Modifying the speed of algorithm dedicated for the detection and making it faster
- Adding JSON output that supports Splunk

# installiton:
```sh
$ git clone https://github.com/MazX0p/ThreatHound.git
$ cd ThreatHound
$ pip install - r requirements.txt
$ pyhton3 ThreatHound.py
```
* Note: glob doesn't support get path of the directory if it has spaces on folder names, please ensure the path of the tool is without spaces (folders names)



# Demo:

https://user-images.githubusercontent.com/54814433/173213830-a32d7264-1615-4943-bad1-76c5763220f0.mp4


![image](https://user-images.githubusercontent.com/54814433/175406514-961a1328-1873-4e6c-973b-0630f6bd8a8a.png)


![image](https://user-images.githubusercontent.com/54814433/209151453-26e657a2-6107-4830-8eea-271af89933ba.png)

![image](https://user-images.githubusercontent.com/54814433/209151521-576115be-44af-4154-b8bc-6265a19a1a65.png)


![image](https://user-images.githubusercontent.com/54814433/209151757-211fb18f-5c0a-42f0-8efb-788d7a48040a.png)



![image](https://user-images.githubusercontent.com/54814433/209151977-07943765-3707-4e18-9aff-b9c2236086a1.png)

