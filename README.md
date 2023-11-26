![Threathound--logo](https://user-images.githubusercontent.com/54814433/209755888-4677f99a-760d-47ea-8764-6994670805a7.png)

# ThreatHound

ThreatHound is an advanced cybersecurity tool designed to facilitate efficient threat detection and analysis, windows events logs. it offers a user-friendly interface for managing and analyzing security data. Key features include log analysis, Sigma rule integration, and real-time threat detection.

# Key Features:
- Automation for Threat hunting, Compromise Assessment, and Incident Response for the Windows Event Logs
- Downloading and updating the Sigma rules daily from the source
- More then 50 detection rules included
- support for more then 2300 detection rules for Sigma
- Support for new sigma rules dynamically and adding it to the detection rulest
- Easily add any detection rules you prefer 
- you can add new event log source type in mapping.py easily
- Sigma Rule Management: Seamlessly manage and process Sigma rules.
  ## V2 Features:
  - Faster!!.
  - Saving of all the outputs in cvs format with full details.
  - searching functionality. 
  - Log Analysis: Analyze logs using custom mappings and filters.
  - User Interface: Intuitive GUI for easy interaction and visualization.
  - Command Interface: you can use command only.
  - Data Visualization: Graphical representation of data for better insights.
  - Real-Time Analysis: Process and analyze data in real-time.
  - Customization: Easily customizable to suit different cybersecurity needs.
  - Compatibility: Cross-platform compatibility with support for different data formats.
  
## Specialized Features for DFIR Professionals:

- **Forensic Data Analysis**: Equipped with capabilities to analyze forensic artifacts, aiding in digital investigations.
- **Incident Response Toolkit**: Provides essential tools for rapid response to security incidents, helping DFIR teams to quickly assess and react to threats.
- **Timeline Analysis**: Supports constructing and analyzing timelines of events, crucial for understanding the sequence of activities during an incident.
- **Artifact Correlation**: Facilitates correlation of various digital artifacts, aiding in the identification of malicious activities and breach points.
- **Log Consolidation and Analysis**: Aggregates and analyzes logs from various sources, providing a comprehensive view of security-related events.
- **Integrations with Forensic Tools**: Offers integration capabilities with popular forensic tools, enhancing its utility in a DFIR context.
  
## Ideal Use Cases:

- **Security Monitoring**: For organizations looking to bolster their security monitoring capabilities, ThreatHound provides real-time analysis and alerts.

- **Incident Investigation**: In the event of a security incident, the tool's deep analysis features enable rapid understanding and response.

- **Compliance and Reporting**: With its comprehensive data handling, ThreatHound assists in maintaining compliance standards and generates detailed reports for auditing purposes.

- **Educational and Training Purposes**: Its user-friendly interface and comprehensive feature set make ThreatHound an excellent tool for educational environments focusing on cybersecurity training.
  
# I’ve built the following:
- A dedicated backend to support Sigma rules for python
- A dedicated backend for parsing evtx for python
- A dedicated backend for match between csv and the Sigma rules
- A dedicated backend to match between evtx and the Sigma rules

# To-do:
- [X] ~~Support for Sigma rules dedicated for DNS query~~  
- [X] ~~Modifying the speed of algorithm dedicated for the detection and making it faster~~  
- [X] ~~Adding csv output that supports SIEMS~~  
- [X] ~~More features~~

# installiton:
```sh
$ git clone https://github.com/MazX0p/ThreatHound.git
$ cd ThreatHound
$ pip3 install - r requirements.txt
$ pyhton3 ThreatHound.py
```
* Note: glob doesn't support get path of the directory if it has spaces on folder names, please ensure the path of the tool is without spaces (folders names)



# Demo:

![tool](https://github.com/MazX0p/ThreatHound/assets/54814433/550e0655-806a-4d7f-80d7-fa87284ac362)


# Screenshots:

# GUI: 

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/fbf8cf46-ce10-46f2-9af4-ea239b0bb5b3)

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/009f9f31-2781-461c-8952-cc69cc7653b9)

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/5a0e1155-8663-45f8-a37f-6b2c9085c000)

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/fec9922c-b00c-4dd1-910c-7d25e06f63e9)

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/7ee7183b-c4d9-4a42-86d6-885c5857ad3b)

# COMMAND LINE:

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/b30a70fc-4e9c-4a27-a556-25976f072714)

![image](https://github.com/MazX0p/ThreatHound/assets/54814433/11f71030-e1be-4a0d-bf6f-731e4b68b774)

