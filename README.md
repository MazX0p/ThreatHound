![Threathound--logo](https://user-images.githubusercontent.com/54814433/209755888-4677f99a-760d-47ea-8764-6994670805a7.png)

# ThreatHound

ThreatHound is an advanced cybersecurity tool designed to facilitate efficient threat detection and analysis. it offers a user-friendly interface for managing and analyzing security data. Key features include log analysis, Sigma rule integration, and real-time threat detection.

# Key Features:
- Automation for Threat hunting, Compromise Assessment, and Incident Response for the Windows Event Logs
- Downloading and updating the Sigma rules daily from the source
- More then 50 detection rules included
- support for more then 2300 detection rules for Sigma
- Support for new sigma rules dynamically and adding it to the detection rules
- Saving of all the outputs in cvs format
- Easily add any detection rules you prefer 
- you can add new event log source type in mapping.py easily
- Sigma Rule Management: Seamlessly manage and process Sigma rules.
  ## V2 Features:
  - Faster!!.
  - Log Analysis: Analyze logs using custom mappings and filters.
  - User Interface: Intuitive GUI for easy interaction and visualization.
  - Data Visualization: Graphical representation of data for better insights.
  - Real-Time Analysis: Process and analyze data in real-time.
  - Customization: Easily customizable to suit different cybersecurity needs.
  - Compatibility: Cross-platform compatibility with support for different data formats.
  

# I’ve built the following:
- A dedicated backend to support Sigma rules for python
- A dedicated backend for parsing evtx for python
- A dedicated backend for match between cvs and the Sigma rules
- A dedicated backend to match between evtx and the Sigma rules

# To-do:
[x] ~~Support for Sigma rules dedicated for DNS query~~ 
[x] ~~Modifying the speed of algorithm dedicated for the detection and making it faster~~
[x] ~~Adding csv output that supports SIEMS~~
[x] ~~More features~~

# installiton:
```sh
$ git clone https://github.com/MazX0p/ThreatHound.git
$ cd ThreatHound
$ pip3 install - r requirements.txt
$ pyhton3 ThreatHound.py
```
* Note: glob doesn't support get path of the directory if it has spaces on folder names, please ensure the path of the tool is without spaces (folders names)



# Demo:

https://user-images.githubusercontent.com/54814433/209446178-7a37f67a-d00b-49fa-adad-17d7658a59e3.mp4

https://player.vimeo.com/video/784137549?h=6a0e7ea68a&amp;badge=0&amp;autopause=0&amp;player_id=0&amp;app_id=58479


# Screenshots:


![image](https://user-images.githubusercontent.com/54814433/209151453-26e657a2-6107-4830-8eea-271af89933ba.png)



![image](https://user-images.githubusercontent.com/54814433/209151521-576115be-44af-4154-b8bc-6265a19a1a65.png)



![image](https://user-images.githubusercontent.com/54814433/209151757-211fb18f-5c0a-42f0-8efb-788d7a48040a.png)


![image](https://user-images.githubusercontent.com/54814433/209151977-07943765-3707-4e18-9aff-b9c2236086a1.png)

