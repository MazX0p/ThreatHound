# total hours i speend here : 8472.1
# contact me if u add more detections
# Mohamed Alzhrani
# https://github.com/MazX0p

import sys
import csv
import re
import io
import json
from netaddr import *
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime, timezone, timedelta
from dateutil.parser import parse
from dateutil.parser import isoparse
from pytz import timezone
import html
import base64
import codecs
import copy
import random
from sigma_manager import GetRuleFilesList
from sigma_manager import GetIsSigmaLoad, SigmaPath
import sigma_manager
import concurrent.futures
from time import sleep
import os
import argparse
from colorama import init, Fore, Style
import platform
from PyQt5.QtWidgets import (
    QApplication, QDialog, QMainWindow, QMessageBox, QWidget, QPushButton, QVBoxLayout, QFileDialog, QTableView, QLineEdit, QItemDelegate
)
from PyQt5.QtCore import Qt, QModelIndex, QSortFilterProxyModel
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QTextDocument
from PyQt5.uic import loadUi
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QTimer
import pandas as pd

try:
    from evtx import PyEvtxParser
    has_evtx = True
except ImportError:
    has_evtx = False

try:
    from lxml import etree
    has_lxml = True
except ImportError:
    has_lxml = False

try:
    import pandas as pd
    has_pandas = True
except ImportError:
    has_pandas = False

def get_os_type():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    else:
        return "Unknown"

os_type = get_os_type()
print("[-] your system : " + os_type)

IsAnalyzing = False
IsSigmaLoaded = False
Result_Event_list = []
Result_Rule_list = []

#=======================
# Initiate list of JSON containing matched rules

Susp_exe=["\\mshta.exe","\\regsvr32.exe","\\csc.exe",'whoami.exe','\\pl.exe','\\nc.exe','nmap.exe','psexec.exe','plink.exe','mimikatz','procdump.exe',' dcom.exe',' Inveigh.exe',' LockLess.exe',' Logger.exe',' PBind.exe',' PS.exe',' Rubeus.exe',' RunasCs.exe',' RunAs.exe',' SafetyDump.exe',' SafetyKatz.exe',' Seatbelt.exe',' SExec.exe',' SharpApplocker.exe',' SharpChrome.exe',' SharpCOM.exe',' SharpDPAPI.exe',' SharpDump.exe',' SharpEdge.exe',' SharpEDRChecker.exe',' SharPersist.exe',' SharpHound.exe',' SharpLogger.exe',' SharpPrinter.exe','EfsPotato.exe',' SharpSC.exe',' SharpSniper.exe',' SharpSocks.exe',' SharpSSDP.exe',' SharpTask.exe',' SharpUp.exe',' SharpView.exe',' SharpWeb.exe',' SharpWMI.exe',' Shhmon.exe',' SweetPotato.exe',' Watson.exe',' WExec.exe','7zip.exe', 'HOSTNAME.EXE', 'hostname.exe']

Susp_commands=['FromBase64String','DomainPasswordSpray','PasswordSpray','Password','Get-WMIObject','Get-GPPPassword','Get-Keystrokes','Get-TimedScreenshot','Get-VaultCredential','Get-ServiceUnquoted','Get-ServiceEXEPerms','Get-ServicePerms','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-UnattendedInstallFiles','Get-Webconfig','Get-ApplicationHost','Get-PassHashes','Get-LsaSecret','Get-Information','Get-PSADForestInfo','Get-KerberosPolicy','Get-PSADForestKRBTGTInfo','Get-PSADForestInfo','Get-KerberosPolicy','Invoke-Command','Invoke-Expression','iex(','Invoke-Shellcode','Invoke--Shellcode','Invoke-ShellcodeMSIL','Invoke-MimikatzWDigestDowngrade','Invoke-NinjaCopy','Invoke-CredentialInjection','Invoke-TokenManipulation','Invoke-CallbackIEX','Invoke-PSInject','Invoke-DllEncode','Invoke-ServiceUserAdd','Invoke-ServiceCMD','Invoke-ServiceStart','Invoke-ServiceStop','Invoke-ServiceEnable','Invoke-ServiceDisable','Invoke-FindDLLHijack','Invoke-FindPathHijack','Invoke-AllChecks','Invoke-MassCommand','Invoke-MassMimikatz','Invoke-MassSearch','Invoke-MassTemplate','Invoke-MassTokens','Invoke-ADSBackdoor','Invoke-CredentialsPhish','Invoke-BruteForce','Invoke-PowerShellIcmp','Invoke-PowerShellUdp','Invoke-PsGcatAgent','Invoke-PoshRatHttps','Invoke-PowerShellTcp','Invoke-PoshRatHttp','Invoke-PowerShellWmi','Invoke-PSGcat','Invoke-Encode','Invoke-Decode','Invoke-CreateCertificate','Invoke-NetworkRelay','EncodedCommand','New-ElevatedPersistenceOption','wsman','Enter-PSSession','DownloadString','DownloadFile','Out-Word','Out-Excel','Out-Java','Out-Shortcut','Out-CHM','Out-HTA','Out-Minidump','HTTP-Backdoor','Find-AVSignature','DllInjection','ReflectivePEInjection','Base64','System.Reflection','System.Management','Restore-ServiceEXE','Add-ScrnSaveBackdoor','Gupt-Backdoor','Execute-OnTime','DNS_TXT_Pwnage','Write-UserAddServiceBinary','Write-CMDServiceBinary','Write-UserAddMSI','Write-ServiceEXE','Write-ServiceEXECMD','Enable-DuplicateToken','Remove-Update','Execute-DNSTXT-Code','Download-Execute-PS','Execute-Command-MSSQL','Download_Execute','Copy-VSS','Check-VM','Create-MultipleSessions','Run-EXEonRemote','Port-Scan','Remove-PoshRat','TexttoEXE','Base64ToString','StringtoBase64','Do-Exfiltration','Parse_Keys','Add-Exfiltration','Add-Persistence','Remove-Persistence','Find-PSServiceAccounts','Discover-PSMSSQLServers','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Mimikatz','powercat','powersploit','PowershellEmpire','GetProcAddress','ICM','.invoke',' -e ','hidden','-w hidden','Invoke-Obfuscation-master','Out-EncodedWhitespaceCommand','Out-Encoded',"-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

Susp_Arguments=["-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

all_suspicious=["\\csc.exe",'whoami.exe','\\pl.exe','\\nc.exe','nmap.exe','psexec.exe','plink.exe','kali','mimikatz','procdump.exe',' dcom.exe',' Inveigh.exe',' LockLess.exe',' Logger.exe',' PBind.exe',' PS.exe',' Rubeus.exe',' RunasCs.exe',' RunAs.exe',' SafetyDump.exe',' SafetyKatz.exe',' Seatbelt.exe',' SExec.exe',' SharpApplocker.exe',' SharpChrome.exe',' SharpCOM.exe',' SharpDPAPI.exe',' SharpDump.exe',' SharpEdge.exe',' SharpEDRChecker.exe',' SharPersist.exe',' SharpHound.exe',' SharpLogger.exe',' SharpPrinter.exe',' SharpRoast.exe',' SharpSC.exe',' SharpSniper.exe',' SharpSocks.exe',' SharpSSDP.exe',' SharpTask.exe',' SharpUp.exe',' SharpView.exe',' SharpWeb.exe',' SharpWMI.exe',' Shhmon.exe',' SweetPotato.exe',' Watson.exe',' WExec.exe','7zip.exe','FromBase64String','DomainPasswordSpray','PasswordSpray','Password','Get-WMIObject','Get-GPPPassword','Get-Keystrokes','Get-TimedScreenshot','Get-VaultCredential','Get-ServiceUnquoted','Get-ServiceEXEPerms','Get-ServicePerms','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-UnattendedInstallFiles','Get-Webconfig','Get-ApplicationHost','Get-PassHashes','Get-LsaSecret','Get-Information','Get-PSADForestInfo','Get-KerberosPolicy','Get-PSADForestKRBTGTInfo','Get-PSADForestInfo','Get-KerberosPolicy','Invoke-Command','Invoke-Expression','iex(','Invoke-Shellcode','Invoke--Shellcode','Invoke-ShellcodeMSIL','Invoke-MimikatzWDigestDowngrade','Invoke-NinjaCopy','Invoke-CredentialInjection','Invoke-TokenManipulation','Invoke-CallbackIEX','Invoke-PSInject','Invoke-DllEncode','Invoke-ServiceUserAdd','Invoke-ServiceCMD','Invoke-ServiceStart','Invoke-ServiceStop','Invoke-ServiceEnable','Invoke-ServiceDisable','Invoke-FindDLLHijack','Invoke-FindPathHijack','Invoke-AllChecks','Invoke-MassCommand','Invoke-MassMimikatz','Invoke-MassSearch','Invoke-MassTemplate','Invoke-MassTokens','Invoke-ADSBackdoor','Invoke-CredentialsPhish','Invoke-BruteForce','Invoke-PowerShellIcmp','Invoke-PowerShellUdp','Invoke-PsGcatAgent','Invoke-PoshRatHttps','Invoke-PowerShellTcp','Invoke-PoshRatHttp','Invoke-PowerShellWmi','Invoke-PSGcat','Invoke-Encode','Invoke-Decode','Invoke-CreateCertificate','Invoke-NetworkRelay','EncodedCommand','New-ElevatedPersistenceOption','wsman','Enter-PSSession','DownloadString','DownloadFile','Out-Word','Out-Excel','Out-Java','Out-Shortcut','Out-CHM','Out-HTA','Out-Minidump','HTTP-Backdoor','Find-AVSignature','DllInjection','ReflectivePEInjection','Base64','System.Reflection','System.Management','Restore-ServiceEXE','Add-ScrnSaveBackdoor','Gupt-Backdoor','Execute-OnTime','DNS_TXT_Pwnage','Write-UserAddServiceBinary','Write-CMDServiceBinary','Write-UserAddMSI','Write-ServiceEXE','Write-ServiceEXECMD','Enable-DuplicateToken','Remove-Update','Execute-DNSTXT-Code','Download-Execute-PS','Execute-Command-MSSQL','Download_Execute','Copy-VSS','Check-VM','Create-MultipleSessions','Run-EXEonRemote','Port-Scan','Remove-PoshRat','TexttoEXE','Base64ToString','StringtoBase64','Do-Exfiltration','Parse_Keys','Add-Exfiltration','Add-Persistence','Remove-Persistence','Find-PSServiceAccounts','Discover-PSMSSQLServers','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Mimikatz','powercat','powersploit','PowershellEmpire','GetProcAddress','ICM','.invoke',' -e ','hidden','-w hidden','Invoke-Obfuscation-master','Out-EncodedWhitespaceCommand','Out-Encoded',"-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass","-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

Susp_Path=['\\temp\\',' C:\Windows\System32\mshta.exe','/temp/','//windows//temp//','/windows/temp/','\\windows\\temp\\','\\appdata\\','/appdata/','//appdata//','//programdata//','\\programdata\\','/programdata/']

Usual_Path=['\\Windows\\','/Windows/','//Windows//','Program Files','\\Windows\\SysWOW64\\','/Windows/SysWOW64/','//Windows//SysWOW64//','\\Windows\\Cluster\\','/Windows/Cluster/','//Windows//Cluster//']

#=======================
#Regex for security logs
MatchedRulesAgainstLogs = dict()

EventID_rex = re.compile('<EventID.*>(.*)<\/EventID>', re.IGNORECASE)

LogonType_rex = re.compile('<Data Name=\"LogonType\">(.*)</Data>|<LogonType>(.*)</LogonType>', re.IGNORECASE)

#======================
# My Regex For Sysmon Logs
User_Name_rex = re.compile('<Data Name=\"User\">(.*)</Data>|<User>(.*)</User>', re.IGNORECASE)
ProcessId_rex = re.compile('<Data Name=\"ProcessId\">(.*)</Data>|<ProcessId>(.*)</ProcessId>', re.IGNORECASE)
DestinationIp_rex = re.compile('<Data Name=\"DestinationIp\">(.*)</Data>|<DestinationIp>(.*)</DestinationIp>', re.IGNORECASE)
Destination_Is_Ipv6_rex = re.compile('<Data Name=\"DestinationIsIpv6\">(.*)</Data>|<DestinationIsIpv6>(.*)</DestinationIsIpv6>', re.IGNORECASE)
Source_IP_SourceIp_rex = re.compile('<Data Name=\"SourceIp\">(.*)</Data>|<SourceIp>(.*)</SourceIp>', re.IGNORECASE)
Source_IP_IpAddress_rex = re.compile('<Data Name=\"IpAddress\">(.*)</Data>|<IpAddress>(.*)</IpAddress>', re.IGNORECASE)
# UtcTime_rex = re.compile('<Data Name=\"UtcTime\">(.*)</Data>|<UtcTime>(.*)</UtcTime>|<TimeCreated SystemTime=\"(.*)\n    </TimeCreated>', re.IGNORECASE)
UtcTime_rex = re.compile('<TimeCreated SystemTime=\"(.*)\">\n    </TimeCreated>', re.IGNORECASE)
Protocol_rex = re.compile('<Data Name=\"Protocol\">(.*)</Data>|<Protocol>(.*)</Protocol>', re.IGNORECASE)
SourcePort_rex = re.compile('<Data Name=\"SourcePort\">(.*)</Data>|<SourcePort>(.*)</SourcePort>', re.IGNORECASE)
DestinationPort_rex = re.compile('<Data Name=\"DestinationPort\">(.*)</Data>|<DestinationPort>(.*)</DestinationPort>', re.IGNORECASE)
SourceHostname_rex = re.compile('<Data Name=\"SourceHostname\">(.*)</Data>|<SourceHostname>(.*)</SourceHostname>', re.IGNORECASE)
FileVersion_rex = re.compile('<Data Name=\"FileVersion\">(.*)</Data>|<FileVersion>(.*)</FileVersion>', re.IGNORECASE)
Description_rex = re.compile('<Data Name=\"Description\">(.*)</Data>|<Description>(.*)</Description>', re.IGNORECASE)
Hashes_rex = re.compile('<Data Name=\"Hashes\">(.*)</Data>|<Hashes>(.*)</Hashes>', re.IGNORECASE)
Computer_Name_rex = re.compile('<Computer>(.*)</Computer>', re.IGNORECASE)
ParentProcessId_rex = re.compile('<Data Name=\"ParentProcessId\">(.*)</Data>|<ParentProcessId>(.*)</ParentProcessId>', re.IGNORECASE)
ParentImage_rex = re.compile('<Data Name=\"ParentImage\">(.*)</Data>|<ParentImage>(.*)</ParentImage>', re.IGNORECASE)
ParentCommandLine_rex = re.compile('<Data Name=\"ParentCommandLine\">(.*)</Data>|<ParentCommandLine>(.*)</ParentCommandLine>', re.IGNORECASE)
GrandparentCommandLine_rex = re.compile('<Data Name=\"GrandparentCommandLine\">(.*)</Data>|<GrandparentCommandLine>(.*)</GrandparentCommandLine>', re.IGNORECASE)
Signed_rex = re.compile('<Data Name=\"Signed\">(.*)</Data>|<Signed>(.*)</Signed>', re.IGNORECASE)
Signature_rex = re.compile('<Data Name=\"Signature\">(.*)</Data>|<Signature>(.*)</Signature>', re.IGNORECASE)
State_rex = re.compile('<Data Name=\"State\">(.*)</Data>|<State>(.*)</State>', re.IGNORECASE)
Status_rex = re.compile('<Data Name=\"Status\">(.*)</Data>|<Status>(.*)</Status>', re.IGNORECASE)
# My Regex For Event Logs
Channel_rex = re.compile('<Channel.*>(.*)<\/Channel>', re.IGNORECASE)
Provider_rex = re.compile('<Provider Name=\"(.*)\" Guid', re.IGNORECASE)
EventSourceName_rex = re.compile('EventSourceName=\"(.*)\"', re.IGNORECASE)
ServiceName_rex = re.compile('<Data Name=\"ServiceName\">(.*)</Data>|<ServiceName>(.*)</ServiceName>', re.IGNORECASE)
Service_Image_Path_rex = re.compile('<Data Name=\"ImagePath\">(.*)</Data>|<ImagePath>(.*)</ImagePath>', re.IGNORECASE)
ServiceType_rex = re.compile('<Data Name=\"ServiceType\">(.*)</Data>|<ServiceType>(.*)</ServiceType>', re.IGNORECASE)
Service_Account_Name_rex = re.compile('<Data Name=\"AccountName\">(.*)</Data>|<AccountName>(.*)</AccountName>', re.IGNORECASE)
ServiceStartType_rex = re.compile('<Data Name=\"StartType\">(.*)</Data>|<StartType>(.*)</StartType>', re.IGNORECASE)
# My Regex for Security logs
AccountName_rex = re.compile('<Data Name=\"SubjectUserName\">(.*)</Data>|<SubjectUserName>(.*)</SubjectUserName>', re.IGNORECASE)
AccountDomain_rex = re.compile('<Data Name=\"SubjectDomainName\">(.*)</Data>|<SubjectDomainName>(.*)</SubjectDomainName>', re.IGNORECASE)
# My NetWork Regex
IpPort_rex = re.compile('<Data Name=\"IpPort\">(.*)</Data>|<IpPort>(.*)</IpPort>', re.IGNORECASE)
# My AD regex
ShareName_rex = re.compile('<Data Name=\"ShareName\">(.*)</Data>|<shareName>(.*)</shareName>', re.IGNORECASE)
ShareLocalPath_rex = re.compile('<Data Name=\"ShareLocalPath\">(.*)</Data>|<ShareLocalPath>(.*)</ShareLocalPath>', re.IGNORECASE)
RelativeTargetName_rex = re.compile('<Data Name=\"RelativeTargetName\">(.*)</Data>|<RelativeTargetName>(.*)</RelativeTargetName>', re.IGNORECASE)
AccountName_Target_rex = re.compile('<Data Name=\"TargetUserName\">(.*)</Data>|<TargetUserName>(.*)</TargetUserName>', re.IGNORECASE)
# My Task regex
TaskName_rex=re.compile('<Data Name=\"TaskName\">(.*)</Data>|<TaskName>(.*)</TaskName>', re.IGNORECASE)
TaskContent_rex = re.compile('<Data Name=\"TaskContent\">([^"]*)</Data>|<TaskContent>([^"]*)</TaskContent>', re.IGNORECASE)
TaskContent2_rex = re.compile('<Arguments>(.*)</Arguments>', re.IGNORECASE)
# My PowerShell regex
Powershell_Command_rex= re.compile('<Data Name=\"ScriptBlockText\">(.*)</Data>', re.IGNORECASE)
# My process Command Line Regex
Process_Command_Line_rex=re.compile('<Data Name=\"CommandLine\">(.*)</Data>|<CommandLine>(.*)</CommandLine>', re.IGNORECASE)
# My New Process Name regex
New_Process_Name_rex=re.compile('<Data Name=\"NewProcessName\">(.*)</Data>', re.IGNORECASE)
# My Regex
TokenElevationType_rex=re.compile('<Data Name=\"TokenElevationType\">(.*)</Data>', re.IGNORECASE)
# My PipeName Regex
PipeName_rex=re.compile("<Data Name=\"PipeName\">(.*)</Data>")
# My ImageName Regex
Image_rex=re.compile("<Data Name=\"Image\">(.*)</Data>")
ServicePrincipalNames_rex=re.compile("<Data Name=\"ServicePrincipalNames\">(.*)</Data>")
SamAccountName_rex=re.compile("<Data Name=\"SamAccountName\">(.*)</Data>")
NewTargetUserName_rex=re.compile("<Data Name=\"NewTargetUserName\">(.*)</Data>")
OldTargetUserName_rex=re.compile("<Data Name=\"OldTargetUserName\">(.*)</Data>")
# My Call Trace regex
CallTrace_rex=re.compile("<Data Name=\"CallTrace\">(.*)</Data>")
# My GrantedAccess Regex
GrantedAccess_rex=re.compile("<Data Name=\"GrantedAccess\">(.*)</Data>")
# My TargetImage Regex
TargetImage_rex=re.compile("<Data Name=\"TargetImage\">(.*)</Data>")
# My SourceImage Regex
SourceImage_rex=re.compile("<Data Name=\"SourceImage\">(.*)</Data>")

SourceProcessId_rex=re.compile("<Data Name=\"SourceProcessId\">(.*)</Data>")
SourceProcessGuid_rex=re.compile("<Data Name=\"SourceProcessGuid\">(.*)</Data>")
TargetProcessGuid_rex=re.compile("<Data Name=\"TargetProcessGuid\">(.*)</Data>")
TargetProcessId_rex=re.compile("<Data Name=\"TargetProcessId\">(.*)</Data>")
PowershellUserId_rex=re.compile("UserId=(.*)")
PowershellHostApplication_rex=re.compile("HostApplication=(.*)")
Powershell_ContextInfo= re.compile('<Data Name=\"ContextInfo\">(.*)</Data>', re.IGNORECASE)
Powershell_Payload= re.compile('<Data Name=\"Payload\">(.*)</Data>', re.IGNORECASE)
Powershell_Path= re.compile('<Data Name=\"Path\">(.*)</Data>', re.IGNORECASE)
Command_Name_rex = re.compile('CommandName = (.*)')
PowerShellCommand_rex = re.compile('<Data>[\s\S]*?</\Data>') # i will come back continue
CommandLine_powershell_rex = re.compile('CommandLine= (.*)')
ScriptName_rex = re.compile('ScriptName=(.*)')
ErrorMessage_rex = re.compile('ErrorMessage=(.*)')
#======================

Security_ID_rex = re.compile('<Data Name=\"SubjectUserSid\">(.*)</Data>|<SubjectUserSid>(.*)</SubjectUserSid>', re.IGNORECASE)
Security_ID_Target_rex = re.compile('<Data Name=\"TargetUserSid\">(.*)</Data>|<TargetUserSid>(.*)</TargetUserSid>', re.IGNORECASE)
Account_Domain_Target_rex = re.compile('<Data Name=\"TargetDomainName\">(.*)</Data>|<TargetDomainName>(.*)</TargetDomainName>', re.IGNORECASE)
Workstation_Name_rex = re.compile('<Data Name=\"WorkstationName\">(.*)</Data>|<WorkstationName>(.*)</WorkstationName>', re.IGNORECASE)
Logon_Process_rex = re.compile('<Data Name=\"LogonProcessName\">(.*)</Data>|<LogonProcessName>(.*)</LogonProcessName>', re.IGNORECASE)
Key_Length_rex = re.compile('<Data Name=\"KeyLength\">(.*)</Data>|<KeyLength>(.*)</KeyLength>', re.IGNORECASE)
AccessMask_rex = re.compile('<Data Name=\"AccessMask\">(.*)</Data>|<AccessMask>(.*)</AccessMask>', re.IGNORECASE)
TicketOptions_rex=re.compile('<Data Name=\"TicketOptions\">(.*)</Data>|<TicketOptions>(.*)</TicketOptions>', re.IGNORECASE)
TicketEncryptionType_rex=re.compile('<Data Name=\"TicketEncryptionType\">(.*)</Data>|<TicketEncryptionType>(.*)</TicketEncryptionType>', re.IGNORECASE)
Group_Name_rex=re.compile('<Data Name=\"TargetUserName\">(.*)</Data>|<TargetUserName>(.*)</TargetUserName>', re.IGNORECASE)
Process_Name_sec_rex = re.compile('<Data Name=\"CallerProcessName\">(.*)</Data>|<CallerProcessName>(.*)</CallerProcessName>|<Data Name=\"ProcessName\">(.*)</Data>|<Data Name=\"NewProcessName\">(.*)</Data>', re.IGNORECASE)
Parent_Process_Name_sec_rex=re.compile('<Data Name=\"ParentProcessName\">(.*)</Data>|<ParentProcessName>(.*)</ParentProcessName>', re.IGNORECASE)
Category_sec_rex= re.compile('<Data Name=\"CategoryId\">(.*)</Data>|<CategoryId>(.*)</CategoryId>', re.IGNORECASE)
Subcategory_rex= re.compile('<Data Name=\"SubcategoryId\">(.*)</Data>|<SubcategoryId>(.*)</LogonType>', re.IGNORECASE)
Changes_rex= re.compile('<Data Name=\"AuditPolicyChanges\">(.*)</Data>|<AuditPolicyChanges>(.*)</AuditPolicyChanges>', re.IGNORECASE)
Member_Name_rex = re.compile('<Data Name=\"MemberName\">(.*)</Data>|<MemberName>(.*)</MemberName>', re.IGNORECASE)
Member_Sid_rex = re.compile('<Data Name=\"MemberSid\">(.*)</Data>|<MemberSid>(.*)</MemberSid>', re.IGNORECASE)
Object_Name_rex = re.compile('<Data Name=\"ObjectName\">(.*)</Data>|<ObjectName>(.*)</ObjectName>', re.IGNORECASE)
ObjectType_rex = re.compile('<Data Name=\"ObjectType\">(.*)</Data>|<ObjectType>(.*)</ObjectType>', re.IGNORECASE)
ObjectServer_rex = re.compile('<Data Name=\"ObjectServer\">(.*)</Data>|<ObjectServer>(.*)</ObjectServer>', re.IGNORECASE)
#=======================
#Regex for windows defender logs

Name_rex = re.compile('<Data Name=\"Threat Name\">(.*)</Data>|<Threat Name>(.*)</Threat Name>', re.IGNORECASE)
Severity_rex = re.compile('<Data Name=\"Severity Name\">(.*)</Data>|<Severity Name>(.*)</Severity Name>', re.IGNORECASE)
Category_rex = re.compile('<Data Name=\"Category Name\">(.*)</Data>|<Category Name>(.*)</Category Name>', re.IGNORECASE)
Path_rex = re.compile('<Data Name=\"Path\">(.*)</Data>|<Path>(.*)</Path>', re.IGNORECASE)
Defender_Remediation_User_rex = re.compile('<Data Name=\"Remediation User\">(.*)</Data>|<Remediation User>(.*)</Remediation User>', re.IGNORECASE)
Defender_User_rex = re.compile('<Data Name=\"User\">(.*)</Data>|<User>(.*)</User>', re.IGNORECASE)
Process_Name_rex = re.compile('<Data Name=\"Process Name\">(.*)</Data>|<Process Name>(.*)</Process Name>', re.IGNORECASE)
Action_rex = re.compile('<Data Name=\"Action ID\">(.*)</Data>|<Action ID>(.*)</Action ID>', re.IGNORECASE)

#=======================
#Regex for system logs

#=======================
#Regex for task scheduler logs
Task_Name = re.compile('<Data Name=\"TaskName\">(.*)</Data>|<TaskName>(.*)</TaskName>', re.IGNORECASE)
Task_Registered_User_rex = re.compile('<Data Name=\"UserContext\">(.*)</Data>|<UserContext>(.*)</UserContext>', re.IGNORECASE)
Task_Deleted_User_rex = re.compile('<Data Name=\"UserName\">(.*)</Data>|<UserName>(.*)</UserName>', re.IGNORECASE)

#======================
#Regex for powershell operational logs
Powershell_ContextInfo= re.compile('<Data Name=\"ContextInfo\">(.*)</Data>', re.IGNORECASE)
Powershell_Payload= re.compile('<Data Name=\"Payload\">(.*)</Data>', re.IGNORECASE)
Powershell_Path= re.compile('<Data Name=\"Path\">(.*)</Data>', re.IGNORECASE)

Host_Application_rex = re.compile('Host Application = (.*)')
#Command_Name_rex = re.compile('Command Name = (.*)')
Command_Type_rex = re.compile('Command Type = (.*)')
Engine_Version_rex = re.compile('Engine Version = (.*)')
User_rex = re.compile('User = (.*)')
Error_Message_rex = re.compile('Error Message = (.*)')

#======================
#Regex for powershell logs
HostApplication_rex = re.compile('HostApplication=(.*)')
CommandLine_rex = re.compile('CommandLine=(.*)')
ScriptName_rex = re.compile('ScriptName=(.*)')
EngineVersion_rex = re.compile('EngineVersion=(.*)')
UserId_rex = re.compile('UserId=(.*)')
ErrorMessage_rex = re.compile('ErrorMessage=(.*)')
#======================
#TerminalServices Local Session Manager Logs
#Source_Network_Address_Terminal_rex= re.compile('Source Network Address: (.*)')
#Source_Network_Address_Terminal_rex= re.compile('<Address>(.*)</Address>')
Source_Network_Address_Terminal_rex= re.compile('<Address>((\d{1,3}\.){3}\d{1,3})</Address>')
Source_Network_Address_Terminal_NotIP_rex= re.compile('<Address>(.*)</Address>')
User_Terminal_rex=re.compile('User>(.*)</User>')
Session_ID_rex=re.compile('<SessionID>(.*)</SessionID>')
#======================
#Microsoft-Windows-WinRM logs
Connection_rex=re.compile('<Data Name=\"connection\">(.*)</Data>|<connection>(.*)</connection>', re.IGNORECASE)
Winrm_UserID_rex=re.compile('<Security UserID=\"(.*)\"', re.IGNORECASE)

#User_ID_rex=re.compile("""<Security UserID=\'(?<UserID>.*)\'\/><\/System>""")
#src_device_rex=re.compile("""<Computer>(?<src>.*)<\/Computer>""")
#======================
#Sysmon Logs
Sysmon_CommandLine_rex=re.compile("<Data Name=\"CommandLine\">(.*)</Data>")
Sysmon_ProcessGuid_rex=re.compile("<Data Name=\"ProcessGuid\">(.*)</Data>")
Sysmon_ProcessId_rex=re.compile("<Data Name=\"ProcessId\">(.*)</Data>")
Sysmon_FileName_rex=re.compile("<Data Name=\"FileName\">(.*)</Data>")
Sysmon_ImageFileName_rex=re.compile("<Data Name=\"ImageFileName\">(.*)</Data>")
Sysmon_Initiated_rex=re.compile("<Data Name=\"Initiated\">(.*)</Data>")
Sysmon_FileVersion_rex=re.compile("<Data Name=\"FileVersion\">(.*)</Data>")
Sysmon_Company_rex=re.compile("<Data Name=\"Company\">(.*)</Data>")
Sysmon_Product_rex=re.compile("<Data Name=\"Product\">(.*)</Data>")
Sysmon_Description_rex=re.compile("<Data Name=\"Description\">(.*)</Data>")
Sysmon_User_rex=re.compile("<Data Name=\"User\">(.*)</Data>")
Sysmon_LogonGuid_rex=re.compile("<Data Name=\"LogonGuid\">(.*)</Data>")
Sysmon_TerminalSessionId_rex=re.compile("<Data Name=\"TerminalSessionId\">(.*)</Data>")
Sysmon_Hashes_MD5_rex=re.compile("<Data Name=\"MD5=(.*),")
Sysmon_Hashes_SHA256_rex=re.compile("<Data Name=\"SHA256=(.*)")
Sysmon_IntegrityLevel_rex=re.compile("<Data Name=\"IntegrityLevel\">(.*)</Data>")
Sysmon_ParentProcessGuid_rex=re.compile("<Data Name=\"ParentProcessGuid\">(.*)</Data>")
Sysmon_ParentProcessId_rex=re.compile("<Data Name=\"ParentProcessId\">(.*)</Data>")
Sysmon_ParentCommandLine_rex=re.compile("<Data Name=\"ParentCommandLine\">(.*)</Data>")
Sysmon_ParentUser_rex=re.compile("<Data Name=\"ParentUser\">(.*)</Data>")
Sysmon_ProviderName_rex=re.compile("<Data Name=\"ProviderName\">(.*)</Data>")
Sysmon_CurrentDirectory_rex=re.compile("<Data Name=\"CurrentDirectory\">(.*)</Data>")
Sysmon_OriginalFileName_rex=re.compile("<Data Name=\"OriginalFileName\">(.*)</Data>")
Sysmon_TargetObject_rex=re.compile("<Data Name=\"TargetObject\">(.*)</Data>")
#########
#Sysmon  event ID 3
Sysmon_Protocol_rex=re.compile("<Data Name=\"Protocol\">(.*)</Data>")
Sysmon_SourceIp_rex=re.compile("<Data Name=\"SourceIp\">(.*)</Data>")
Sysmon_SourceHostname_rex=re.compile("<Data Name=\"SourceHostname\">(.*)</Data>")
Sysmon_SourcePort_rex=re.compile("<Data Name=\"SourcePort\">(.*)</Data>")
Sysmon_DestinationIp_rex=re.compile("<Data Name=\"DestinationIp\">(.*)</Data>")
Sysmon_DestinationHostname_rex=re.compile("<Data Name=\"DestinationHostname\">(.*)</Data>")
Sysmon_DestinationPort_rex=re.compile("<Data Name=\"DestinationPort\">(.*)</Data>")

#########
#Sysmon  event ID 8
Sysmon_StartFunction_rex=re.compile("<Data Name=\"StartFunction\">(.*)</Data>")
Sysmon_StartModule_rex=re.compile("<Data Name=\"StartModule\">(.*)</Data>")

#########
Sysmon_ImageLoaded_rex=re.compile("<Data Name=\"ImageLoaded\">(.*)</Data>")
Sysmon_Details_rex=re.compile("<Data Name=\"Details\">(.*)</Data>")
Sysmon_GrantedAccess_rex=re.compile("<Data Name=\"GrantedAccess\">(.*)</Data>")
Sysmon_CallTrace_rex=re.compile("<Data Name=\"CallTrace\">(.*)</Data>")

##########

Security_Authentication_Summary=[{'User':[],'SID':[],'Number of Successful Logins':[]}]
Logon_Events=[{'Date and Time':[],'timestamp':[],'Event ID':[],'Account Name':[],'Account Domain':[],'Logon Type':[],'Logon Process':[],'Source IP':[],'Workstation Name':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]

EVTX_HEADER = b"\x45\x6C\x66\x46\x69\x6C\x65\x00"
evtx_list = []
user_list = []
user_list_2 = []
sourceIp_list = []
sourceIp_list_2 = []
#cve-2021-42287 Detect
REQUEST_TGT_CHECK_list = []
New_Target_User_Name_Check_list = []
SAM_ACCOUNT_NAME_CHECK_list = []
ATTACK_REPLAY_CHECK_list = []


# IPv4 regex
IPv4_PATTERN = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z", re.DOTALL)

# IPv6 regex
IPv6_PATTERN = re.compile(r"\A(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,5})?|([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,4})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,3})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){0,2})?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::(([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3}))?)?|:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})(::([0-9a-f]|[1-9a-f][0-9a-f]{1,3})?|(:([0-9a-f]|[1-9a-f][0-9a-f]{1,3})){3}))))))\Z", re.DOTALL)

evtx_list2 = ["/mnt/c/Users/ahmad/Desktop/biz/project/downloads/EVTX-ATTACK-SAMPLES-master/Discovery/discovery_psloggedon.evtx"]

#detect base64 commands
def isBase64(command):
    try:
        return base64.b64encode(base64.b64decode(command)) == command
    except Exception:
        return False

def to_lxml(record_xml):
    rep_xml = record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
    fin_xml = rep_xml.encode("utf-8")
    parser = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(fin_xml, parser)

def xml_records(filename):
    evtx = None
    if evtx is None:
        with open(filename, "rb") as evtx:
            parser = PyEvtxParser(evtx)
            for record in parser.records():
                try:
                    yield to_lxml(record["data"]), None
                except etree.XMLSyntaxError as e:
                    yield record["data"], e

def checker(check):
    if check == "REQUEST_TGT_CHECK":
        REQUEST_TGT_CHECK_list.append("True")
    if check == "New_Target_User_Name_Check":
        New_Target_User_Name_Check_list.append("True")
    if check == "SAM_ACCOUNT_NAME_CHECK":
        SAM_ACCOUNT_NAME_CHECK_list.append("True")
    if check == "ATTACK_REPLAY_CHECK":
        ATTACK_REPLAY_CHECK_list.append("True")

def event_sanity_check(field):
    if isinstance(field,list):
        if len(field) == 0:
            return field
        else:
            if isinstance(field[0],tuple):
                return field[0][0]
            else:
                return field[0]
    elif isinstance(field,tuple):
        return field[0]
    elif isinstance(field,str):
        return field

def field_filter(field,key):
    # add logic here to filter fields and troubleshoot
    if key == "Hashes":
        md5 = ""
        sha1 = ""
        sha256 = ""
        imphash = ""
        if len(field) == 0:
            return md5, sha1, sha256, imphash
        else:
            hashes = field.split(",")
            for hash in hashes:
                if hash.startswith("MD5="):
                    md5 = hash.strip("MD5=")
                if hash.startswith("SHA1="):
                    sha1 = hash.strip("SHA1=")
                if hash.startswith("SHA256="):
                    sha256 = hash.strip("SHA256=")
                if hash.startswith("IMPHASH="):
                    imphash = hash.strip("IMPHASH=")
            return md5, sha1, sha256, imphash

def check_type(object, type_name):
    if str(type(object)).find(type_name) != -1:
        return True

    return False        

def get_value_from_list(rex, record_data):
    obj_list = rex.findall(record_data)

    result = []
    try:
        if check_type(obj_list, "list") and len(obj_list) > 0:
            if check_type(obj_list[0], "list"):
                if len(obj_list[0]) > 1 and len(obj_list[0][1]) > 0:
                    result = obj_list[0][1].strip()
                elif len(obj_list[0][0]) > 0:
                    result = obj_list[0][0].strip()
            elif check_type(obj_list[0], "str"):
                if len(obj_list) > 1 and len(obj_list[1]) > 0:
                    result = obj_list[1].strip()
                elif len(obj_list[0]) > 0:
                    result = obj_list[0].strip()
            else:
                result = obj_list
        else:
            result = obj_list
    except Exception as e:
        print("[-] get_value_from_list: error= " + str(e))
        print(rex)

    return result

def change_key_names(json_object, key_mapping):
    """
    Change key names in a JSON object based on the provided mapping.

    Parameters:
    - json_object: The input JSON object.
    - key_mapping: A dictionary specifying the mapping from old keys to new keys.

    Returns:
    - A new JSON object with updated key names.
    """
    if not isinstance(json_object, dict):
        # If the input is not a dictionary, return it unchanged
        return json_object

    new_object = {}
    for old_key, value in json_object.items():
        new_key = key_mapping.get(old_key, old_key)
        if isinstance(value, dict):
            # If the value is a nested dictionary, recursively update its keys
            new_value = change_key_names(value, key_mapping)
        elif isinstance(value, list):
            # If the value is a list, recursively update keys in list items
            new_value = [change_key_names(item, key_mapping) for item in value]
        else:
            new_value = value
        new_object[new_key] = new_value

    return new_object

def change_array(json_array, key_mapping):
    new_array = []
    for json_object in json_array:
        new_array.append(change_key_names(json_object, key_mapping))

    return new_array
    
field_mapping = {
    "ProcessId": "ProcessId",
    "Level": "Level",
    "Task Category": "Task Category",
    "RuleName": "RuleName",
    "ProcessGuid": "ProcessGuid",
    "Image": "Image",
    "UtcTime": "Timestamp",
    "Event ID": "EventID",
    "FileVersion": "FileVersion",
    "Description": "Description",
    "Product": "Product",
    "Company": "Company",
    "OriginalFileName": "OriginalFileName",
    "CommandLine": "Command_line",
    "CurrentDirectory": "CurrentDirectory",
    "User": "User",
    "LogonGuid": "LogonGuid",
    "LogonId": "LogonId",
    "TerminalSessionId": "TerminalSessionId",
    "IntegrityLevel": "IntegrityLevel",
    "Hashes": "Hashes",
    "ParentProcessGuid": "ParentProcessGuid",
    "ParentProcessId": "ParentProcessId",
    "ParentImage": "ParentImage",
    "ParentCommandLine": "pid"
    # ... add other mappings as needed
}

def csv_string_to_json(file):
    f = open(file, mode="r", encoding="utf-8")
    csv_string = f.read()
    f.close()

    csv_string = csv_string.replace("\ufeff", "")

    data = []
    # Create a file-like object from the CSV string
    csv_file = io.StringIO(csv_string)

    # Read CSV data
    csv_reader = csv.DictReader(csv_file)
    data = [row for row in csv_reader]


    # Convert to JSON
    json_data_string = json.dumps(data, indent=2)

    json_data = json.loads(json_data_string)

    for i in range(len(json_data)):
        if 'null' in json_data[i]:
            json_temp = convert_log_to_json(json_data[i]['null'][0])

            for key, value in json_temp.items():
                json_data[i][key] = value

    json_data = change_array(json_data, field_mapping)

    return json_data

def parse_timestamp(timestamp_str):
    # Convert timestamp string to datetime object
    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')

def parse_hashes(hashes_str):
    # Split the hashes string into a list of key-value pairs
    hash_pairs = hashes_str.split(', ')
    # Create a dictionary from the key-value pairs
    return {key: value for key, value in [pair.split('=') for pair in hash_pairs]}

def convert_log_to_json(log_text):
    # Define a regex pattern to extract key-value pairs
    pattern = re.compile(r'(\w+): (.+?)\n')
    
    # Use regex to find all key-value pairs in the log text
    matches = pattern.findall(log_text)

    # Create a dictionary from the matches
    log_dict = dict(matches)

    # Convert specific fields to appropriate types
    #log_dict['UtcTime'] = parse_timestamp(log_dict['UtcTime'])
    #log_dict['Hashes'] = parse_hashes(log_dict['Hashes'])

    return log_dict

#========================================== END OF SPRAY Detect

#def sigmahq():
    ## we need to convert the .yml to varible
    ## store all .yml files values to them varible
    ## compare the .yml varible values with .xml varible values
    ## prin tthe result with .yml tag value.

def print_colored(text, color):
    print(color + text + Style.RESET_ALL)

from colorama import Fore

def LOGO():
    bcolor_random = [Fore.RED, Fore.CYAN, Fore.MAGENTA, Fore.BLUE, Fore.YELLOW,
                    Fore.GREEN]
    random.shuffle(bcolor_random)
    x = bcolor_random[0] + """

████████╗██╗░░██╗██████╗░███████╗░█████╗░████████╗  ██╗░░██╗░█████╗░██╗░░░██╗███╗░░██╗██████╗░
╚══██╔══╝██║░░██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝  ██║░░██║██╔══██╗██║░░░██║████╗░██║██╔══██╗
░░░██║░░░███████║██████╔╝█████╗░░███████║░░░██║░░░  ███████║██║░░██║██║░░░██║██╔██╗██║██║░░██║
░░░██║░░░██╔══██║██╔══██╗██╔══╝░░██╔══██║░░░██║░░░  ██╔══██║██║░░██║██║░░░██║██║╚████║██║░░██║
░░░██║░░░██║░░██║██║░░██║███████╗██║░░██║░░░██║░░░  ██║░░██║╚█████╔╝╚██████╔╝██║░╚███║██████╔╝
░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░  ╚═╝░░╚═╝░╚════╝░░╚═════╝░╚═╝░░╚══╝╚═════╝░

\n"""

    for c in x:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0004)
    y = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in y:
        print(Fore.RED + c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    y = "\t||                   THREAT HOUND                   ||\n"
    for c in y:
        print(Fore.WHITE + c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    x = "\t||                                                  ||\n"
    for c in x:
        print(Fore.WHITE + c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    z = "\t||        This Tool Made BY: Mohamed Alzhrani       ||\n"
    for c in z:
        print(Fore.WHITE + c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    y = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in y:
        print(Fore.RED + c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    y = "\t||              http://github.com/MazX0p            ||\n"
    for c in y:
        print(Fore.WHITE + c, end='')
        sys.stdout.flush()
        sleep(0.0005)

    y = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in y:
        print(Fore.RED + c, end='')
        sys.stdout.flush()
        sleep(0.0065)

    print(Fore.GREEN + c)

def list_files(startpath):
    filelist = []
    for root, dirs, files in os.walk(startpath):
        for f in files:
            if f.find(".evtx") != -1 or f.find(".csv") != -1:
                #print(root + "\\" + f)
                if get_os_type() == "Windows":
                    filelist.append(root + "/" + f)
                else:
                    filelist.append(root + "\\" + f)

    return filelist

def parse_arguments():
    parser = argparse.ArgumentParser(description="THREAT HOUND")

    # Add arguments
    parser.add_argument("--path", help="Path to the file(evtx, csv) or directory", required=False)
    parser.add_argument("--sigma", "-s", help="Path of custom sigma folder", required=False)
    parser.add_argument("--form", "-f", action="store_true", help="Display a form", required=False)
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.path == None and args.form == None:
        parser.print_help()
        sys.exit(1)

    return args

class CustomFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.filter_value = ""

    def setFilterValue(self, value):
        self.filter_value = value
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        # Override the filter method to check for exact match
        for column in range(self.sourceModel().columnCount()):
            index = self.sourceModel().index(source_row, column, source_parent)
            text = self.sourceModel().data(index, Qt.DisplayRole)
            if self.filter_value.lower() == text.lower():
                return True
        return False

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1532, 861)
        self.horizontalLayoutWidget = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(20, 20, 721, 41))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.horizontalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.lineEdit = QtWidgets.QLineEdit(self.horizontalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)

        self.pushButton = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.show_folder_dialog)
        self.horizontalLayout.addWidget(self.pushButton)

        self.pushButton_2 = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_2.clicked.connect(self.show_file_dialog)
        self.horizontalLayout.addWidget(self.pushButton_2)

        self.horizontalLayoutWidget_2 = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(750, 20, 761, 41))
        self.horizontalLayoutWidget_2.setObjectName("horizontalLayoutWidget_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")

        self.label_2 = QtWidgets.QLabel(self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)

        self.lineEdit_2 = QtWidgets.QLineEdit(self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.horizontalLayout_2.addWidget(self.lineEdit_2)

        self.pushButton_4 = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_4.setFont(font)
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_4.clicked.connect(self.show_folder_dialog_sigma)
        self.horizontalLayout_2.addWidget(self.pushButton_4)

        self.pushButton_3 = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_3.clicked.connect(self.do_start)
        #self.pushButton_3.clicked.connect(self.start_progress)
        self.horizontalLayout_2.addWidget(self.pushButton_3)

        # Create the data model
        self.model = QStandardItemModel(self)

        # Set headers
        self.model.setHorizontalHeaderLabels(["DateTime", "EventID", "User", "Other", "RuleId"])

        self.tableView = QtWidgets.QTableView(Form)
        self.tableView.setGeometry(QtCore.QRect(580, 100, 931, 711))
        self.tableView.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableView.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableView.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerItem)
        self.tableView.setObjectName("tableView")

        # Set the model to the QTableView
        self.tableView.setModel(self.model)

        # Create a proxy model for filtering
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.tableView.setModel(self.proxy_model)

        """
        # Create a proxy model for filtering
        self.proxy_model = CustomFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.tableView.setModel(self.proxy_model)
        """

        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setGeometry(QtCore.QRect(1190, 70, 131, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.lineEdit_3 = QtWidgets.QLineEdit(Form)
        self.lineEdit_3.setPlaceholderText("Search...")
        self.lineEdit_3.textChanged.connect(self.filter_data)
        self.lineEdit_3.setGeometry(QtCore.QRect(1340, 70, 167, 25))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_3.setFont(font)
        self.lineEdit_3.setObjectName("lineEdit_3")

        # Create the data model
        self.model_rule = QStandardItemModel(self)

        # Set headers
        self.model_rule.setHorizontalHeaderLabels(["Count", "RuleName", "FalsePositives"])

        self.tableView_rule = QtWidgets.QTableView(Form)
        self.tableView_rule.setGeometry(QtCore.QRect(20, 100, 551, 711))
        self.tableView_rule.setObjectName("tableView_rule")

        # Set the model to the QTableView
        self.tableView_rule.setModel(self.model_rule)

        # Click event for all rows
        self.tableView_rule.clicked.connect(self.handle_table_click)

        self.pushButton_showall = QtWidgets.QPushButton(Form)
        self.pushButton_showall.setGeometry(QtCore.QRect(1250, 70, 75, 27))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_showall.setFont(font)
        self.pushButton_showall.setObjectName("pushButton_showall")
        self.pushButton_showall.clicked.connect(self.click_button_showall)

        self.pushButton_save = QtWidgets.QPushButton(Form)
        self.pushButton_save.setGeometry(QtCore.QRect(1160, 70, 75, 27))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_save.setFont(font)
        self.pushButton_save.setObjectName("pushButton_save")
        self.pushButton_save.clicked.connect(self.click_button_save)

        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(20, 820, 551, 29))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_3.setFont(font)
        self.label_3.setLineWidth(50)
        self.label_3.setObjectName("label_3")
        self.progressBar = QtWidgets.QProgressBar(Form)
        self.progressBar.setGeometry(QtCore.QRect(578, 830, 971, 21))
        self.progressBar.setProperty("value", 24)
        self.progressBar.setObjectName("progressBar")
        self.start_progress()

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def detect_events_security_log(self, file_name):
        global Result_Event_list
        global Result_Rule_list
        global MatchedRulesAgainstLogs

        MatchedRulesAgainstLogs = dict()
        
        x = 100 / len(file_name)
        pos = 0

        for file in file_name:
            Event_list = []

            if file.find(".evtx") != -1:
                print("[-] parsing file: " + file)
                parser = PyEvtxParser(file)

                """
                max_threads = 100
                
                # Define parameters for your tasks
                params_list = [(record, 1) for record in parser.records()]

                print("[-] detect_events_security_log: len(params_list)= " + str(len(params_list)))

                with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
                    futures = [executor.submit(analysis_record, i, *params) for i, params in enumerate(params_list)]
                    #futures = [executor.submit(task, i, ) for i in range(RuleFilesList)]

                    # Wait for all tasks to complete
                    concurrent.futures.wait(futures)
                """

                for record in parser.records():
                    record_data = record['data']
                    EventID = EventID_rex.findall(record_data)

                    #Parsing starts here
                    if len(EventID) > 0:
                        LogonType = get_value_from_list(LogonType_rex, record_data)
                        UtcTime = get_value_from_list(UtcTime_rex, record_data)
                        UserName_2 = get_value_from_list(User_Name_rex, record_data)
                        IpAddress = get_value_from_list(Source_IP_IpAddress_rex, record_data)
                        SourceIp = get_value_from_list(Source_IP_SourceIp_rex, record_data)
                        Destination_IP = get_value_from_list(DestinationIp_rex, record_data)
                        SourcePort = get_value_from_list(SourcePort_rex, record_data)
                        IpPort = get_value_from_list(IpPort_rex, record_data)
                        DestinationPort = get_value_from_list(DestinationPort_rex, record_data)
                        SourceHostname = get_value_from_list(SourceHostname_rex, record_data)
                        ProcessId = get_value_from_list(ProcessId_rex, record_data)
                        Protocol = get_value_from_list(Protocol_rex, record_data)
                        Command_line = get_value_from_list(Process_Command_Line_rex, record_data)
                        FileVersion = get_value_from_list(FileVersion_rex, record_data)
                        Hashes = get_value_from_list(Hashes_rex, record_data)
                        Description = get_value_from_list(Description_rex, record_data)
                        Computer_Name = get_value_from_list(Computer_Name_rex, record_data)
                        Computer = Computer_Name_rex.findall(record_data)
                        ParentProcessId = get_value_from_list(ParentProcessId_rex, record_data)
                        ParentImage = get_value_from_list(ParentImage_rex, record_data)
                        ParentCommandLine = get_value_from_list(ParentCommandLine_rex, record_data)
                        ParentCommandLine = html.unescape(ParentCommandLine)
                        Channel = get_value_from_list(Channel_rex, record_data)
                        ProviderName = get_value_from_list(Provider_rex, record_data)
                        EventSourceName = get_value_from_list(EventSourceName_rex, record_data)
                        ServiceName = get_value_from_list(ServiceName_rex, record_data)
                        Service_Image_Path = get_value_from_list(Service_Image_Path_rex, record_data)
                        ServiceType = get_value_from_list(ServiceType_rex, record_data)
                        ServiceStartType = get_value_from_list(ServiceStartType_rex, record_data)
                        Service_Account_Name = get_value_from_list(Service_Account_Name_rex, record_data)
                        Account_Name = get_value_from_list(AccountName_rex, record_data)
                        Account_Domain = get_value_from_list(AccountDomain_rex, record_data)
                        ShareName = get_value_from_list(ShareName_rex, record_data)
                        ShareLocalPath = get_value_from_list(ShareLocalPath_rex, record_data)
                        RelativeTargetName = get_value_from_list(RelativeTargetName_rex, record_data)
                        Task_Name = get_value_from_list(TaskName_rex, record_data)
                        TargetAccount_Name = get_value_from_list(AccountName_Target_rex, record_data)
                        Target_Account_Domain = get_value_from_list(Account_Domain_Target_rex, record_data)
                        Workstation_Name = get_value_from_list(Workstation_Name_rex, record_data)
                        PowerShell_Command = get_value_from_list(Powershell_Command_rex, record_data)
                        New_Process_Name = get_value_from_list(New_Process_Name_rex, record_data)
                        TokenElevationType = get_value_from_list(TokenElevationType_rex, record_data)
                        PipeName = get_value_from_list(PipeName_rex, record_data)
                        ImageName = get_value_from_list(Image_rex, record_data)
                        ServicePrincipalNames = get_value_from_list(ServicePrincipalNames_rex, record_data)
                        SamAccountName = get_value_from_list(SamAccountName_rex, record_data)
                        NewTargetUserName = get_value_from_list(NewTargetUserName_rex, record_data)
                        OldTargetUserName = get_value_from_list(OldTargetUserName_rex, record_data)
                        TargetProcessId = get_value_from_list(TargetProcessId_rex, record_data)
                        TargetProcessGuid = get_value_from_list(TargetProcessGuid_rex, record_data)
                        SourceProcessGuid = get_value_from_list(SourceProcessGuid_rex, record_data)
                        SourceProcessId = get_value_from_list(SourceProcessId_rex, record_data)
                        SourceImage = get_value_from_list(SourceImage_rex, record_data)
                        TargetImage = get_value_from_list(TargetImage_rex, record_data)
                        GrantedAccess = get_value_from_list(GrantedAccess_rex, record_data)
                        CallTrace = get_value_from_list(CallTrace_rex, record_data)
                        PowershellUserId = get_value_from_list(PowershellUserId_rex, record_data)
                        PowershellHostApplication = get_value_from_list(PowershellHostApplication_rex, record_data)
                        Command_Name = get_value_from_list(Command_Name_rex, record_data)
                        CommandLine_powershell = get_value_from_list(CommandLine_powershell_rex, record_data)
                        PowerShellCommand = get_value_from_list(PowerShellCommand_rex, record_data)
                        ScriptName = get_value_from_list(ScriptName_rex, record_data)
                        #====================
                        Logon_Process = get_value_from_list(Logon_Process_rex, record_data)
                        Key_Length = get_value_from_list(Key_Length_rex, record_data)
                        Security_ID = get_value_from_list(Security_ID_rex, record_data)
                        Process_Name = get_value_from_list(Process_Name_sec_rex, record_data)
                        Object_Name = get_value_from_list(Object_Name_rex, record_data)
                        ObjectType = ObjectType_rex.findall(record_data)
                        ObjectServer = ObjectServer_rex.findall(record_data)

                        AccessMask = AccessMask_rex.findall(record_data)

                        Task_Content = str(TaskContent_rex.findall(record_data))
                        Task_arguments = get_value_from_list(re.compile("Arguments(.*)/Arguments"), Task_Content)
                        Task_Command = get_value_from_list(re.compile("Command(.*)/Command"), Task_Content)

                        ##The function will probably be called here . Just adding the comment for now.
                        ### Create JSON of Event
                        Event = {
                            "Timestamp" : UtcTime,
                            "EventID" : EventID,
                            "Computer_Name" : Computer_Name,
                            "AccessMask" : AccessMask,
                            "AccountName" : Service_Account_Name,
                            "Action" : Action_rex.findall(record_data),
                            "AuditPolicyChanges" : Changes_rex.findall(record_data),
                            "CallTrace" : CallTrace,
                            "CallerProcessName":Process_Name,
                            "Channel" : Channel,
                            "CommandLine" : Sysmon_CommandLine_rex.findall(record_data),
                            "Company" : Sysmon_Company_rex.findall(record_data),
                            "ContextInfo" : Powershell_ContextInfo.findall(record_data),
                            "CurrentDirectory" : Sysmon_CurrentDirectory_rex.findall(record_data),
                            "Description" : Description,
                            "DestinationHostname" : Sysmon_DestinationHostname_rex.findall(record_data),
                            "DestinationIp" : Destination_IP,
                            "DestinationIsIpv6" : Destination_Is_Ipv6_rex.findall(record_data),
                            "DestinationPort" : DestinationPort,
                            "Details" : Sysmon_Details_rex.findall(record_data),
                            "EngineVersion" : EngineVersion_rex.findall(record_data),
                            "FileName" : Sysmon_FileName_rex.findall(record_data),
                            "FileVersion" : FileVersion,
                            "GrantedAccess" : GrantedAccess,
                            "GrandparentCommandLine" : GrandparentCommandLine_rex.findall(record_data),
                            "Hashes" : Hashes,
                            "HostApplication" : HostApplication_rex.findall(record_data),
                            "Image" : ImageName,
                            "ImageFileName" : Sysmon_ImageFileName_rex.findall(record_data),
                            "ImageLoaded" : Sysmon_ImageLoaded_rex.findall(record_data),
                            "ImagePath" : Service_Image_Path,
                            "Initiated" : Sysmon_Initiated_rex.findall(record_data),
                            "IntegrityLevel" : Sysmon_IntegrityLevel_rex.findall(record_data),
                            "IpAddress" : IpAddress,
                            "KeyLength" : Key_Length,
                            "LogonProcessName" : Logon_Process,
                            "LogonType" : LogonType,
                            "NewTargetUserName" : NewTargetUserName,
                            "ObjectName" : Object_Name,
                            "ObjectServer" : ObjectServer,
                            "ObjectType" : ObjectType,
                            "OldTargetUserName" : OldTargetUserName,
                            "OriginalFileName" : Sysmon_OriginalFileName_rex.findall(record_data),
                            "ParentCommandLine" : ParentCommandLine,
                            "ParentImage" : ParentImage,
                            "ParentUser" : Sysmon_ParentUser_rex.findall(record_data),
                            "Path" : Path_rex.findall(record_data),
                            "Payload" : Powershell_Payload.findall(record_data),
                            "PipeName" : PipeName,
                            "ProcessId" : ProcessId,
                            "Product" : Sysmon_Product_rex.findall(record_data),
                            "Protocol" : Protocol,
                            "ProviderName" : ProviderName,
                            "RelativeTargetName" : RelativeTargetName,
                            "SamAccountName" : SamAccountName,
                            "ScriptBlockText" : PowerShell_Command,
                            "ServiceName" : ServiceName,
                            "ServicePrincipalNames" : ServicePrincipalNames,
                            "ServiceStartType" : ServiceStartType,
                            "ServiceType" : ServiceType,
                            "ShareName" : ShareName,
                            "Signed" : Signed_rex.findall(record_data),
                            "Signature" : Signature_rex.findall(record_data),
                            "SourceImage" : SourceImage,
                            "SourceIp" : SourceIp,
                            "SourcePort" : SourcePort,
                            "EventSourceName" : EventSourceName,
                            "StartFunction" : Sysmon_StartFunction_rex.findall(record_data),
                            "StartModule" : Sysmon_StartModule_rex.findall(record_data),
                            "State" : State_rex.findall(record_data),
                            "Status" : Status_rex.findall(record_data),
                            "SubjectDomainName" : Account_Domain,
                            "SubjectUserName" : Account_Name,
                            "SubjectUserSid" : Security_ID,
                            "TargetImage" : TargetImage,
                            "TargetObject" : Sysmon_TargetObject_rex.findall(record_data),
                            "TargetUserName" : TargetAccount_Name,
                            "TargetUserSid" : Security_ID_Target_rex.findall(record_data),
                            "Task_Name" : Task_Name,
                            "TicketEncryptionType" : TicketEncryptionType_rex.findall(record_data),
                            "TicketOptions" : TicketOptions_rex.findall(record_data),
                            "User" : UserName_2,
                            "UserName_2" : UserName_2,
                            "UserName" : Task_Deleted_User_rex.findall(record_data),
                            "WorkstationName" : Workstation_Name,
                            "ParentProcessId" : ParentProcessId,
                            "Command_line" : Command_line,
                            "Task_arguments" : Task_arguments,
                            "Task_Command" : Task_Command,
                            "Target_Account_Domain" : Target_Account_Domain,
                            "PowerShellCommand" : PowerShellCommand,
                            "CommandLine_powershell" : CommandLine_powershell,
                            "PowershellHostApplication" : PowershellHostApplication,
                            "PowershellUserId" : PowershellUserId,
                            "ScriptName" : ScriptName,
                            "New_Process_Name" : New_Process_Name,
                            "SourceProcessId" : SourceProcessId,
                            "TargetProcessId" : TargetProcessId
                        }

                        Event_list.append(Event)
            elif file.find(".csv") != -1:
                Event_list = csv_string_to_json(file)

            y = x / len(Event_list)
            for Event in Event_list:
                pos = pos + y

                if hasattr(self, "progressBar"):
                    self.progressBar.setValue(int(pos))

                PASS = False
                PASS1 = False
                EventID = Event["EventID"]

                if not "Command_line" in Event:
                    Event['Command_line'] = ""

                if not "Computer_Name" in Event:
                    Event['Computer_Name'] = ""

                if not "CommandLine" in Event:
                    Event['CommandLine'] = Event['Command_line']

                if not "ParentCommandLine" in Event:
                    Event['ParentCommandLine'] = ""

                if not "UserName" in Event:
                    if "User" in Event:
                        Event['UserName'] = Event["User"]
                    else:
                        Event['UserName'] = ""

                if not "SourceIp" in Event:
                    Event['SourceIp'] = ""

                if not "DestinationIp" in Event:
                    Event['DestinationIp'] = ""

                if not "DestinationIp" in Event:
                    Event['DestinationIp'] = ""

                for key in Event:
                    Event[key] = event_sanity_check(Event[key])

                if "Hashes" in Event:
                    # minor field corrections
                    Event["md5"], Event["sha1"], Event["sha256"], Event["Imphash"] = field_filter(Event["Hashes"], "Hashes")
                    #Event.pop('Hashes', None)
                else:
                    Event["md5"] = ""
                    Event["sha1"] = ""
                    Event["sha256"] = ""
                    Event["Imphash"] = ""

                #check for matched rules
                #Loader function

                #print(Event)
                Matched_Rules = sigma_manager.MatchRules(Event)

                #print("\n[-] MatchRules: Scanning end len(Matched_Rules)= " + str(len(Matched_Rules)))
                #exit(0)
                #if len(Matched_Rules) > 0:
                #    input()

                if len(Matched_Rules) == 0:
                    pass
                else:
                    for matched_rule in range(0,len(Matched_Rules)):
                        rule_title = Matched_Rules[matched_rule]["title"]
                        if "falsepositives" in Matched_Rules[matched_rule]:
                            rule_fp = Matched_Rules[matched_rule]["falsepositives"]
                        else:
                            rule_fp = ["None"]
                        if rule_title in MatchedRulesAgainstLogs.keys():
                            MatchedRulesAgainstLogs[rule_title]["Events"].append(Event)
                        else:
                            MatchedRulesAgainstLogs[rule_title] = {
                                "falsepositives" : rule_fp,
                                "Events" : list()
                            }
                            MatchedRulesAgainstLogs[rule_title]["Events"].append(Event)

                #Detect any log that contain suspicious process name or argument
                if EventID[0]=="3":
                    try:
                        for i in Susp_exe:
                           if i in record_data.lower():
                               print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                               print_colored(" Found Suspicios "+ i +" Process Make TCP Connection", Fore.RED)
                               print(" [+] Source IP : ( %s ) \n " % Event['SourceIp'], end='')
                               print(" [+] Source Port : ( %s ) \n " % Event['SourcePort'], end='')
                               print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                               print(" [+] Host Name : ( %s ) \n " % Event['SourceHostname'], end='')
                               print(" [+] Destination IP : ( %s ) \n " % Event['DestinationIp'], end='')
                               print(" [+] Destination port : ( %s ) \n " % Event['DestinationPort'], end='')
                               print(" [+] Protocol : ( %s ) \n " % Event['Protocol'], end='')
                               print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                               print("____________________________________________________\n")

                               PASS = True
                               Suspicios_Event3 = i

                    except Exception as e:
                        pass

                elif EventID[0]=="1" and PASS== True:
                    try:
                        hashes = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', Event['Hashes'])
                        MD5 = hashes[0].strip()

                        print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                        print_colored(" The Creation Process from "+ Suspicios_Event3 +"", Fore.RED)
                        print(" [+] Command Line : ( %s ) \n " % Event['Command_line'] , end='')
                        print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                        print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                        print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                        print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                        print(" [+] Description : ( %s ) \n " % Event['Description'], end='')
                        print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                        print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                        print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                        print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                        print("____________________________________________________\n")

                        # Detect LethHTA
                        if "mshta.exe" in Event['Command_line'] and "svchost.exe -k DcomLaunch" in Event['ParentCommandLine']:
                            print_colored(" LethalHTA Detected !!", Fore.RED)
                            print("[+] \033[0;31;47mBy Process ID "+ Event['ProcessId'] +"", Fore.RED)

                    except Exception as e:
                        pass

                # Detect PowershellRemoting via wsmprovhost
                if EventID[0]=="10":
                    try:
                        hashes = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', Event['Hashes'])
                        MD5 = hashes[0].strip()

                        # Detect PowershellRemoting via wsmprovhost
                        if "wsmprovhost.exe" in Event['ParentImage'] and "wsmprovhost.exe -Embedding" in Event['ParentCommandLine']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" PowershellRemoting via wsmprovhost Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Event['Command_line'] , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")
                    except Exception as e:
                        pass

                # Detect WinPwnage
                if EventID[0]=="1":
                    Command_unescape = html.unescape(Event['Command_line'])
                    try:
                        hashes = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', Event['Hashes'])
                        MD5 = hashes[0].strip()

                        # Detect PowershellRemoting via wsmprovhost
                        if "wsmprovhost.exe" in Event['ParentImage'] and "wsmprovhost.exe -Embedding" in Event['ParentCommandLine']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" PowershellRemoting via wsmprovhost Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Event['Command_line'] , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")


                        # Detect Network Connection via Compiled HTML
                        if "RunHTMLApplication" in Command_unescape and "hh.exe" in Event['ParentImage'] and "chm" in Event['ParentCommandLine'] and "mshtml" in Command_unescape:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" Network Connection via Compiled HTML Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                        # Detect WinPwnage python
                        if "cmd.exe" in Event['ParentImage'] and "winpwnage.py" in Event['Command_line'] and "-u execute" in Event['Command_line'] and "python" in Event['Image'] or "-u execute" in Event['Command_line'] and "python" in Event['Image']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" WinPwnage Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape, end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                        # Detect WinPwnage ieframe.dll,OpenURL
                        if "rundll32.exe" in Event['Command_line'] and "ieframe.dll,OpenURL" in Event['Command_line'] and "rundll32.exe" in Event['Image']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" WinPwnage UAC BAYPASS by ieframe.dll,OpenURL Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                        # Detect WinPwnage url.dll,OpenURL
                        if "rundll32.exe" in Event['Command_line'] and "url.dll,OpenURL" in Event['Command_line'] and "rundll32.exe" in Event['Image']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" WinPwnage UAC BAYPASS by url.dll,OpenURL Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape, end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")


                        # Detect WinPwnage url.dll,FileProtocolHandler
                        if "rundll32.exe" in Event['Command_line'] and "url.dll,FileProtocolHandler" in Event['Command_line'] and "rundll32.exe" in Event['Image']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" WinPwnage UAC BAYPASS by url.dll,FileProtocolHandler Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                        # Detect suspicious mshta.exe
                        if "mshta.exe" in Event['Image']: # TODO make it more strong, and check the rundll32 of it
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" Suspicios mshta.exe Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                        # Detect suspicious winlogon.exe SMBV3 CVE-2020-0769
                        # For me: Comment on the detections later to make them more generic
                        if "winlogon.exe" in Event['ParentImage'] and "cmd.exe" in Event['Image'].lower(): # TODO make it more strong, and check the rundll32 of it
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" SMBV3 CVE-2020-0769 !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape, end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                # Detect Remote Service
                elif EventID[0]=="7045":
                    try:
                        # Detect Remote Service Start
                        if "Service Control Manager" in Event['ProviderName'] and "Service Control Manager" in Event['EventSourceName'] and "remotesvc" in Event['ServiceName'] or "spoolsv" in Event['ServiceName'] or "spoolfool" and "user mode service" in Event['ServiceType']:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" Remote Service Start Detect !!", Fore.RED)
                            print(" [+] Computer : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] channel : ( %s ) \n " % Event['Channel'], end='')
                            print(" [+] Service Name: ( %s ) \n " % Event['ServiceName'], end='')
                            print(" [+] Started Process : ( %s ) \n " % Event['ImagePath'], end='')
                            print(" [+] Service Type : ( %s ) \n " % Event['ServiceType'], end='')
                            print(" [+] Account Name : ( %s ) \n " % Event['AccountName'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                # detect winrm code execution
                elif EventID[0]=="800":
                    try:
                        if len(Channel[0])>0:
                            PowerShellCommand = html.unescape(Event['PowerShellCommand'])
                            CommandLine_powershell = html.unescape(Event['CommandLine_powershell'])
                            PowerShellCommand_All = html.unescape(str(Event))
                            PowershellHostApplication = html.unescape(Event['PowershellHostApplication'])
                            PowerShellCommand = re.findall(r' (.*)', PowerShellCommand)
                            words = [r"Invoke-Mimikatz.ps1"]
                            results = [x for x in PowerShellCommand if all(re.search("\\b{}\\b".format(w), x) for w in words)]
                            results = results[0].strip()

                        # detect winrm code execution can you show where i have to work
                        if 1 == 1:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" Winrm Detect !!", Fore.RED)# we need voice call yes
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'] , end='')
                            print(" [+] channel : ( %s ) \n " % Event['Channel'], end='')
                            print(" [+] user Name: ( %s ) \n " % Event['PowershellUserId'], end='')
                            #print(" [+] Command Name: ( %s ) \n " % Command_Name, end='')
                            print(" [+] PowerShell Script: ( %s ) \n " % Event['ScriptName'], end='')
                            print(" [+] PowerShell Mode: ( %s ) \n " % CommandLine_powershell, end='')
                            print(" [+] PowerShell Command: ( %s ) \n " % PowershellHostApplication, end='')
                            for element in PowerShellCommand:
                                if 'name="Arguments"' in element:
                                    print(" [+] PowerShell OutPut: \n ", end='')
                                    print(element.split('value')[1])
                            print("____________________________________________________\n")

                        # detect winrm code execution can you show where i have to work
                        if  results != None:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" Winrm Invoke-Mimikatz Detect !!", Fore.RED)
                            print(" [+] Computer Name: ( %s ) \n " % Event['Computer_Name'] , end='')
                            print(" [+] channel : ( %s ) \n " % channel, end='')
                            print(" [+] user Name: ( %s ) \n " % Event['PowershellUserId'], end='')
                            print(" [+] PowerShell Command: ( %s ) \n " % PowershellHostApplication, end='')
                            print(" [+] PowerShell Script: ( %s ) \n " % Event['ScriptName'], end='')
                            print(" [+] Mimikatz Command: ( %s ) \n " % results, end='')
                            print(bcolor.RED + " [+] PowerShell OutPut:\n ", end='')
                            for element in PowerShellCommand:
                                print(bcolor.CBLUE + element, end='\n')
                            print("____________________________________________________\n")

                    except Exception as e:
                        #print(e)
                        pass

                # Detect Remote Task Creation
                elif EventID[0]=="5145":
                    try:
                        # Detect Remote Task Creation via ATSVC named pipe
                        if "atsvc" in RelativeTargetName:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" Suspicios ATSVC Detect !!", Fore.RED)
                            print(" [+] Computer Name: ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] channel : ( %s ) \n " % Event['Channel'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Account Domain Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] Source IP : ( %s ) \n " % Event['IpAddress'], end='')
                            print(" [+] Source Port : ( %s ) \n " % IpPort, end='')
                            print(" [+] Share Name : ( %s ) \n " % Event['ShareName'], end='')
                            print(" [+] Local Share Path : ( %s ) \n " % ShareLocalPath, end='')
                            print(" [+] File Path : ( %s ) \n " % Evnet['RelativeTargetName'], end='')
                            print("____________________________________________________\n")

                            PASS1 = True


                    except Exception as e:
                        pass

                    # Detect Remote Task Creation via ATSVC named pipe
                elif EventID[0] == "4698" or EventID[0] == "4699" and PASS1 == True:
                    try:
                        print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                        print_colored(" Remote Task Creation via ATSVC named pipe Detect !!", Fore.RED)
                        print(" [+] Computer Name: ( %s ) \n " % Event['Computer_Name'], end='')
                        print(" [+] channel : ( %s ) \n " % Event['Channel'], end='')
                        print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                        print(" [+] Task Name : ( %s ) \n " % Event['Task_Name'], end='')
                        print(" [+] Task Command : ( %s ) \n " % Event['Task_Command'], end='')
                        print(" [+] Task Command Arguments : ( %s ) \n " % Event['Task_arguments'], end='')
                        print("____________________________________________________\n")
                    except Exception as e:
                        pass

                # Kerberos AS-REP Attack Detect
                if EventID[0] == "4768":
                    try:
                        if Event['ServiceName'] == "krbtgt":
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" Kerberos AS-REP Attack Detected !", Fore.RED)
                            print("[+] User Name : ( %s ) \n" % Event['TargetUserName'], end='')
                            print(" [+] Computer Name: ( %s ) \n" % Event['Computer_Name'], end='')
                            print(" [+] Channel : ( %s ) \n" % Event['Channel'], end='')
                            print(" [+] Service Name : ( %s ) \n" % Event['ServiceName'], end='')
                            print(" [+] Domain Name : ( %s ) \n" % Event['Target_Account_Domain'], end='')
                            print(" [+] Source IP : ( %s ) \n " % Event['IpAddress'], end='')
                            print(" [+] Source Port : ( %s ) \n" % IpPort, end='')
                            print("____________________________________________________\n")
                    except Exception as e:
                        pass

                # PowerShell Download Detect
                if EventID[0] == "4104": # TODO Base64 command Detect
                    try:
                        if len(Computer[0])>0:
                            Command = html.unescape(Event['ScriptBlockText'])

                        IsEncoded = True
                        #check if command is encoded
                        if isBase64(Command) == False:
                            IsEncoded = False

                            #check if  download start
                        if IsEncoded == False and "IEX(New-Object Net.WebClient).downloadString" in Event['ScriptBlockText'] or "(New-Object Net.WebClient)" in Event['ScriptBlockText'] or "[System.NET.WebRequest]" in Event['ScriptBlockText']:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print_colored(" PowerShell Download Detect !", Fore.RED)
                            print("[+] PowerShell Command : ( %s ) \n" % Command, end='')
                            print(" [+] Computer : ( %s ) \n" % Event['Computer_Name'], end='')
                            print(" [+] Channel : ( %s ) \n" % Event['Channel'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect suspicious process Runing PowerShell Command
                if EventID[0]=="4688":
                    Command_unescape = html.unescape(Event['Command_line'])
                    try:
                        Base64Finder = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', Command_unescape)

                        if "powershell.exe" in Command_unescape.lower() or "powershell" in Command_unescape.lower() and "%%1936" in TokenElevationType: #and "cmd.exe" in Process_Name.lower():
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" [+] Found Suspicios Process Runing PowerShell Command On Full Privilege", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            if len(Base64Finder[0])>5:
                               print(" [+] Base64 Command : ( %s ) \n " % Base64Finder[0], end='')
                            print("____________________________________________________\n")
                        # PipeName
                        pipe = r'\.\pipe'
                        # SMBEXEC
                        SMBEXEC = r'cmd.exe /q /c echo cd'
                        SMBEXEC2 = r'\\127.0.0.1\c$'
                        wmiexec = r'cmd.exe /q /c'
                        wmiexec2 = r'1> \\127.0.0.1\admin$\__'
                        wmiexec3 = r'2>&1'
                        msiexec = r'msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=asdasd /qn'
                        msiexec2 = r'comsvcs.dll MiniDump  C:\windows\temp\logctl.zip full'
                        msiexec3 = r'windows\temp\ekern.exe'
                        #Detect Privilege esclation "GetSystem"
                        if "cmd.exe /c echo" in Command_unescape.lower() and "%%1936" in TokenElevationType and "cmd.exe" in Event['CallerProcessName'].lower() and pipe in Command_unescape.lower():
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" GetSystem Detect By metasploit & Cobalt Strike & Empire & PoshC2", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")
                        #Detect Cmd.exe command
                        if "cmd.exe" in Command_unescape.lower() and "%%1936" in TokenElevationType and "cmd.exe" in Event['CallerProcessName'].lower():
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" Found Suspicios Process Runing cmd Command On Full Privilege", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                        #Detect SMBEXEC
                        if SMBEXEC in Command_unescape.lower() and SMBEXEC2 in Command_unescape.lower() and wmiexec3 in Command_unescape.lower() and "%%1936" in TokenElevationType:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" SMBEXEC Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                        #Detect wmiexec variation
                        if wmiexec in Command_unescape.lower() and wmiexec2 in Command_unescape.lower() and "%%1936" in TokenElevationType:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" WMIEXEC Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                        #Detect CVE-2021-44077
                        if msiexec in Command_unescape:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" CVE-2021-44077 first stage Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                        #Detect CVE-2021-44077 second
                        if msiexec2 in Command_unescape:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" CVE-2021-44077 2th stage Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                        #Detect CVE-2021-44077 3th
                        if msiexec3 in Command_unescape:
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" [+] CVE-2021-44077 3th stage Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect Privilege esclation "GetSystem"
                if EventID[0]=="7045":
                    try:
                        # PipeName
                        pipe = r'\.\pipe'
                        #Detect Privilege esclation "GetSystem"
                        if "cmd.exe /c echo" in Command_unescape.lower() and "%%1936" in TokenElevationType and "cmd.exe" in Event['New_Process_Name'].lower() and pipe in Command_unescape.lower():
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                            print_colored(" GetSystem Detect By metasploit & Cobalt Strike & Empire & PoshC2", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['SubjectDomainName'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['SubjectUserName'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Process Name : ( %s ) \n " % Event['New_Process_Name'], end='')
                            print(" [+] Process Command Line : ( %s ) \n " % Command_unescape, end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect PsExec execution
                if EventID[0]=="1":
                    try:
                        hashes = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', Event['Hashes'])
                        MD5 = hashes[0].strip()

                        # Detect PsExec
                        if "psexesvc.exe" in Event['ParentImage'].lower() or "psexesvc.exe" in Event['ParentCommandLine'].lower():
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" Psexesvc execution Detected !!", Fore.RED)
                            print(" [+] Command Line : ( %s ) \n " % Command_unescape , end='')
                            print(" [+] Parent Process Command Line : ( %s ) \n " % Event['ParentCommandLine'], end='')
                            print(" [+] User Name : ( %s ) \n " % Event['UserName_2'], end='')
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] File Info : ( %s ) \n " % Event['FileVersion'], end='')
                            print(" [+] description : ( %s ) \n " % Event['Description'], end='')
                            print(" [+] Process MD5 : ( %s ) \n " % MD5, end='')
                            print(" [+] ParentImage Path : ( %s ) \n " % Event['ParentImage'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] Parent Process ID : ( %s ) \n " % Event['ParentProcessId'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect PsExec Pipe Connection
                if EventID[0]=="18":
                    try:
                        # Detect PsExec Pipe Connection
                        if "\psexesvc" in Event['PipeName'].lower() and "stderr" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdin" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdout" in Event['PipeName'].lower():
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" PsExec Pipe Connection Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] Image Name : ( %s ) \n " % Event['Image'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] PipeName : ( %s ) \n " % Event['PipeName'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect PsExec Pipe Creation
                if EventID[0]=="17":
                    try:
                        # Detect PsExec Pipe Creation
                        if "\psexesvc" in Event['PipeName'].lower() and "stderr" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdin" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdout" in Event['PipeName'].lower():
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" PsExec Pipe Creation Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] Image Name : ( %s ) \n " % Event['Image'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] PipeName : ( %s ) \n " % Event['PipeName'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect PsExec Pipe Creation
                if EventID[0]=="17":
                    try:
                        if len(Computer_Name[0])>0:
                            Event['Timestamp'] = UtcTime[0][0].strip()

                        # Detect PsExec Pipe Creation
                        if "\psexesvc" in Event['PipeName'].lower() and "stderr" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdin" in Event['PipeName'].lower() or "\psexesvc" in Event['PipeName'].lower() and "stdout" in Event['PipeName'].lower():
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" PsExec Pipe Creation Detected !!", Fore.RED)
                            print(" [+] Computer Name : ( %s ) \n " % Event['Computer_Name'], end='')
                            print(" [+] Image Name : ( %s ) \n " % Event['Image'], end='')
                            print(" [+] Process ID : ( %s ) \n " % Event['ProcessId'], end='')
                            print(" [+] PipeName : ( %s ) \n " % Event['PipeName'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Detect SMBV3 CVE-2020-0769
                if EventID[0]=="10":
                    try:
                        # Detect SMBV3 CVE-2020-0769
                        if "0x1fffff" in Event['GrantedAccess'] and "winlogon.exe" in Event['TargetImage'] and "ntdll.dll" in Event['CallTrace'] and "KERNELBASE.dll" in Event['CallTrace']:
                            print("\n__________ " + Event['Timestamp'] + " __________ \n\n ", end='')
                            print_colored(" START OF CVE-2020-0769 Detected !!", Fore.RED)
                            print(" [+] Source Process Id : ( %s ) \n " % Event['SourceProcessId'], end='')
                            print(" [+] Source Image : ( %s ) \n " % Event['SourceImage'], end='')
                            print(" [+] Target Process Id : ( %s ) \n " % Event['TargetProcessId'], end='')
                            print(" [+] Target Image : ( %s ) \n " % Event['TargetImage'], end='')
                            print(" [+] Granted Access : ( %s ) \n " % Event['GrantedAccess'], end='')
                            print(" [+] CallTrace : ( %s ) \n " % Event['CallTrace'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #detect pass the hash
                if EventID[0] == "4625" or EventID[0] == "4624":
                    try:
                        #print(Logon_Events)
                        user=Event['SubjectUserName']

                        if logon_type == "3" or logon_type == "9" and Event['TargetUserName'] != "ANONYMOUS LOGON" and Event['KeyLength'] == "0":
                            print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                            print("[+] \033[0;31;47mPass The Hash Detected", Fore.RED)
                            print("[+] User Name : ( %s ) \n" % Event['TargetUserName'], end='')
                            print(" [+] Computer : ( %s ) \n" % Event['Computer_Name'], end='')
                            print(" [+] Channel : ( %s ) \n" % Event['Channel'], end='')
                            print(" [+] Account Domain : ( %s ) \n" % Event['Target_Account_Domain'], end='')
                            print(" [+] Logon Type : ( %s ) \n" % Event['LogonType'], end='')
                            print(" [+] Logon Process : ( %s ) \n" % Event['LogonProcessName'], end='')
                            print(" [+] Source IP : ( %s ) \n " % Event['IpAddress'], end='')
                            print(" [+] Workstation Name : ( %s ) \n" % Event['WorkstationName'], end='')
                            print("____________________________________________________\n")

                    except Exception as e:
                        pass

                #Start Of Detecting cve-2021-42287
                if EventID[0]=="4741": #+ EventID[0]=="4673" + EventID[0]=="4742" + EventID[0]=="4781" + EventID[0]=="4768" + EventID[0]=="4781" and EventID[0]=="4769":
                    try:
                        if "-" in Event['ServicePrincipalNames']:
                            checker("ATTACK_REPLAY_CHECK")

                    except Exception as e:
                        pass


                # Detecting Sam Account name changed to domain controller name
                if EventID[0]=="4742":
                    try:
                        UserName = Event['TargetUserName']
                        if "-" not in Event['SamAccountName']:
                            checker("SAM_ACCOUNT_NAME_CHECK")

                    except Exception as e:
                        pass

                # Verify Sam Account name changed to domain controller name
                if EventID[0]=="4781":
                    try:
                        if Event['NewTargetUserName'] in Event['Computer_Name']:
                             checker("New_Target_User_Name_Check")

                    except Exception as e:
                        pass

                # Kerberos AS-REP Attack Detect
                if EventID[0] == "4768":
                    try:
                        if serviceName == "krbtgt":
                            checker("REQUEST_TGT_CHECK")

                    except Exception as e:
                        pass

                ################ end of CVE-2021-42278 DETECTION

                #detect PasswordSpray Attack
                if EventID[0] == "4648":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Event['SubjectUserName']

                        #For Defrinceation
                        user_list.append(user)
                        user_list_2.append(user)
                        sourceIp_list.append(Event['SourceIp'])
                        sourceIp_list_2.append(Event['SourceIp'])

                    except Exception as e:
                        pass
                
            # FULL CVE-2021-42278 DETECTION
            if "True" in REQUEST_TGT_CHECK_list and "True" in New_Target_User_Name_Check_list and "True" in SAM_ACCOUNT_NAME_CHECK_list and "True" in ATTACK_REPLAY_CHECK_list:
                parser = PyEvtxParser(file)
                for record in parser.records():
                    record_data = record['data']
                    EventID2 = EventID_rex.findall(record_data)
                    NewTargetUserName = NewTargetUserName_rex.findall(record_data)
                    OldTargetUserName = OldTargetUserName_rex.findall(record_data)
                    Computer_Name = Computer_Name_rex.findall(record_data)
                    Target_Account_Domain=Account_Domain_Target_rex.findall(record_data)
                    Account_Name = AccountName_rex.findall(record_data)

                    if len(EventID2) > 0:
                        if EventID2[0] == "4781":
                            try:
                                if len(Account_Name[0])>0:
                                    NewTargetUserName = NewTargetUserName[0].strip()
                                    computer = Computer_Name[0].strip()
                                    OldTargetUserName = OldTargetUserName[0].strip()
                                    accountName = Account_Name[0][0].strip()

                                if OldTargetUserName in computer: #and "True" in REQUEST_TGT_CHECK_list and "True" in New_Target_User_Name_Check_list:# and "True" in SAM_ACCOUNT_NAME_CHECK_list and "True" in ATTACK_REPLAY_CHECK_list:
                                    print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='')
                                    print_colored(" CVE-2021-42287 and CVE-2021-42278 DETCTED !!", Fore.RED)
                                    print(" [+] Computer Name : ( %s ) \n " % computer, end='')
                                    print(" [+] User Name : ( %s ) \n " % accountName, end='')
                                    print(" [+] New User Name : ( %s ) \n " % NewTargetUserName, end='')
                                    print(" [+] Old User Name : ( %s ) \n " % OldTargetUserName, end='')
                                    print(" [+] Domain Name : ( %s ) \n " % Target_Account_Domain, end='')
                                    print("____________________________________________________\n")


                            except Exception as e:
                                pass
        #### END

        # For Defrinceation and Detect the attack
        if range(len(user_list)) == range(len(user_list_2)) and range(len(sourceIp_list)) == range(len(sourceIp_list_2)):
            SprayUserDetector = 0
            for x in range(len(user_list)):
                if user_list[x] == user_list_2[x]:
                    SprayUserDetector += 1

            if SprayUserDetector >= 10:
                print("\n__________ " + record["timestamp"] + " __________ \n\n ", end='') ### Fix Time
                print("[+] \033[0;31;47mPassword Spray Detected!!", Fore.RED)
                print("[+] Attacker User Name : ( %s ) \n" % user, end='')
                print(" [+] Account Domain : ( %s ) \n" % target_account_domain, end='')
                print(" [+] Source IP : ( %s ) \n" % source_ip, end='')
                print(" [+] Number Of Spray : ( %s ) \n" % SprayUserDetector, end='')
                print("____________________________________________________\n")

        #### print the final report of the SIGMA scanning
        Result_Rule_list = []
        Result_Event_list = []

        try:
            for RuleName in MatchedRulesAgainstLogs.keys():
                print(f"[!] Rule Name: {RuleName}", end="\t\t\t\t\t\t\n")
                print(f"  [-] Potential False-Positives: {MatchedRulesAgainstLogs[RuleName]['falsepositives']}")
                
                Result_Rule = {}
                Result_Rule['RuleName'] = RuleName
                Result_Rule['Counts'] = len(MatchedRulesAgainstLogs[RuleName]["Events"])
                Result_Rule['FalsePositives'] = str(MatchedRulesAgainstLogs[RuleName]['falsepositives'])
                Result_Rule_list.append(Result_Rule)

                count = 0
                for Event in MatchedRulesAgainstLogs[RuleName]["Events"]:
                    New_Event = {}
                    
                    for key in Event.keys():
                        if key  in Event:
                            New_Event[key] = Event[key]
                    
                    New_Event['RuleName'] = RuleName
                    New_Event['RuleId'] = RuleName + Result_Rule['FalsePositives'][2:7]
                    New_Event['FalsePositives'] = Result_Rule['FalsePositives']

                    if "Timestamp" in Event and len(Event["Timestamp"]) != 0:
                        print("\n__________ " + str(Event["Timestamp"]) + " __________ \n\n ")
                    else:
                        print("\n__________ no time __________ \n\n ")
                    if len(Event["EventID"]) != 0:
                        print("     [*] EventID: " + str(Event["EventID"]))
                    if "Computer_Name" in Event and len(Event["Computer_Name"]) != 0:
                        print("     [*] Computer: " + str(Event["Computer_Name"]))
                    if "Image" in Event and len(Event["Image"]) != 0:
                        print("     [*] Process Image: " + str(Event["Image"]))
                    if "CommandLine" in Event and len(Event["CommandLine"]) != 0:
                        print("     [*] CommandLine: " + str(Event["CommandLine"]))
                    if "ParentImage" in Event and len(Event["ParentImage"]) != 0:
                        print("     [*] Parent Process Image: " + str(Event["ParentImage"]))
                    if "ParentCommandLine" in Event and len(Event["ParentCommandLine"]) != 0:
                        print("     [*] Parent Process CommandLine: " + str(Event["ParentCommandLine"]))
                    if "User" in Event and len(Event["User"]) != 0:
                        print("     [*] User: " + str(Event["User"]))
                    if "UserName" in Event and len(Event["UserName"]) != 0:
                        print("     [*] UserName: " + str(Event["UserName"]))
                    if "SourceIp" in Event and len(Event["SourceIp"]) != 0:
                        print("     [*] Source IP Address: " + str(Event["SourceIp"]) + ":" + str(Event["SourcePort"]))
                    if "DestinationIp" in Event and len(Event["DestinationIp"]) != 0:
                        print("     [*] Destionation IP Address: " + str(Event["DestinationIp"]) + ":" + str(Event["DestinationPort"]))
                    if "OriginalFileName" in Event and len(Event["OriginalFileName"]) != 0:
                        print("     [*] Original File Name: " + str(Event["OriginalFileName"]))
                    if "SubjectUserName" in Event and len(Event["SubjectUserName"]) != 0:
                        print("     [*] Subject User Name: " + str(Event["SubjectUserName"]))
                    if "TargetUserName" in Event and len(Event["TargetUserName"]) != 0:
                        print("     [*] Target User Name: " + str(Event["TargetUserName"]))
                    if "SubjectDomainName" in Event and len(Event["SubjectDomainName"]) != 0:
                        print("     [*] Subject Domain Name: " + str(Event["SubjectDomainName"]))
                    if "Product" in Event and len(Event["Product"]) != 0:
                        print("     [*] Product: " + str(Event["Product"]))
                    if "MD5" in Event and len(Event["MD5"]) != 0:
                        print("     [*] MD5: " + str(Event["MD5"]))
                    if "SHA1" in Event and len(Event["SHA1"]) != 0:
                        print("     [*] SHA1: " + str(Event["SHA1"]))
                    if "SHA256" in Event and len(Event["SHA256"]) != 0:
                        print("     [*] SHA256: " + str(Event["SHA256"]))
                    if "IMPHASH" in Event and len(Event["IMPHASH"]) != 0:
                        print("     [*] IMPHASH: " + str(Event["IMPHASH"]))

                    Result_Event_list.append(New_Event)
                    print("____________________________________________________\n")
                    print("____________________________________________________\n")

                #if count != Result_Rule['Counts']:
        except Exception as ERROR:
            print(str(ERROR))
            print_colored("Error printing the Matched Rules", Fore.RED)
            exit(0)

        return Result_Rule_list, Result_Event_list
    
    # Print the list of all rules that match. Each rule key contains all corresponding events that matched
    # print(MatchedRulesAgainstLogs.keys())
    # You can use this variable MatchedRulesAgainstLogs any way you want

    # Parsing Evtx File
    def parse_evtx(self, evtx_list):
        try:
            # count = 0
            # record_sum = 0
            # evtx = None
            # for evtx_file in evtx_list:
            #     if evtx is None:
            #         with open(evtx_file, "rb") as fb:
            #             fb_data = fb.read(8)
            #             if fb_data != EVTX_HEADER:
            #                 sys.exit("[!] This file is not EVTX format {0}.".format(evtx_file))

            #         with open(evtx_file, "rb") as evtx:
            #             parser = PyEvtxParser(evtx)
            #             records = list(parser.records())
            #             record_sum += len(records)

            # print("[+] Last record number is {0}.".format(record_sum))

            # # Parse Event log
            # print("[+] Start parsing the EVTX file.")

            # for evtx_file in evtx_list:
            #     print("[+] Parse the EVTX file {0}.".format(evtx_file))

            #     for record, err in xml_records(evtx_file):
            #         if err is not None:
            #             continue
            #         count += 1

            #         if evtx_file == evtx_file:
            #             sys.stdout.write("\r[+] Now loading {0} records.".format(count))
            #             sys.stdout.flush()

            return self.detect_events_security_log(evtx_list)
        except Exception as e:
            print_colored("Exception Occurred", Fore.RED)
            print_colored(str(e), Fore.RED)
            print_colored("Opps !", Fore.RED)
            print_colored("Enter a Correct Path", Fore.RED)

    def main_func(self, file):
        filelist = []

        if file.find(".evtx") == -1 and file.find(".csv") == -1:
            if os.path.isdir(file):
                filelist = list_files(file)
            else:
                print_colored ("[-] error: input dirctory path correctly.", Fore.RED)
                sys.exit(1)
        elif os.path.isfile(file):
            filelist.append(file)
        else:
            print_colored ("[-] error: input file path correctly. " + file, Fore.RED)

            sys.exit(1)

        start_datetime = datetime.now()
        self.parse_evtx(filelist)

        end_datetime = datetime.now()
        # Calculate the time difference
        time_difference = end_datetime - start_datetime

        # Convert the time difference to milliseconds
        milliseconds = time_difference.total_seconds() * 1000
        print_colored ("[-] time= " + str(milliseconds), Fore.GREEN)

        return milliseconds

    def start_progress(self):
        self.progressBar.setValue(0)  # Reset the progress bar

        # Use a QTimer to simulate progress over time
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(100)  # Update every 100 milliseconds

    def update_progress(self):
        """
        current_value = self.progress_bar.value()
        if current_value < 100:
            self.progress_bar.setValue(current_value + 1)
        else:
            self.timer.stop()
        """
        pass

    def filter_data(self):
        filter_text = self.lineEdit_3.text()
        self.proxy_model.setFilterRegExp(filter_text)
        self.proxy_model.setFilterKeyColumn(-1)
        result_count = self.proxy_model.rowCount()
        self.label_3.setText(f"Result Count: {result_count}")
        self.tableView.resizeColumnsToContents()
        self.tableView.resizeRowsToContents()

    def do_start(self):
        global IsSigmaLoaded
        global IsAnalyzing
        global Result_Rule_list
        global Result_Event_list

        if IsSigmaLoaded == False:
            self.label_3.setText(f"No Sigma, Please load it.")
            return

        if IsAnalyzing == True:
            self.label_3.setText(f"working now, try later")
            return

        IsAnalyzing = True

        sel_text = self.lineEdit.text()
        
        #self.model_rule.removeRows(0, self.model_rule.rowCount())
        #self.model.removeRows(0, self.model.rowCount())
        self.model_rule.clear()
        self.model.clear()

        Result_Rule_list = []
        Result_Event_list = []

        if len(sel_text) > 0:
            #result_rule_list, result_event_list, milliseconds = main_func(sel_text)
            milliseconds = self.main_func(sel_text)

            for Rule in Result_Rule_list:
                item1 = QStandardItem(str(Rule['Counts']))
                item2 = QStandardItem(Rule['RuleName'])
                item3 = QStandardItem(Rule['FalsePositives'])

                self.model_rule.appendRow([item1, item2, item3])

            self.tableView_rule.resizeColumnsToContents()
            self.tableView_rule.resizeRowsToContents()

            cnt = 0
            for Event in Result_Event_list:
                # Add sample data
                other = ""
                if "Computer_Name" in Event and len(str(Event["Computer_Name"])) != 0:
                    other = other + "Computer: " + str(Event["Computer_Name"]) + "\n"
                if "Image" in Event and len(Event["Image"]) != 0:
                    other = other + "Process Image: " + str(Event["Image"]) + "\n"
                if "CommandLine" in Event and len(Event["CommandLine"]) != 0:
                    other = other + "CommandLine: " + str(Event["CommandLine"]) + "\n"
                if "ParentImage" in Event and len(Event["ParentImage"]) != 0:
                    other = other + "Parent Process Image: " + str(Event["ParentImage"]) + "\n"
                if "ParentCommandLine" in Event and len(Event["ParentCommandLine"]) != 0:
                    other = other + "Parent Process CommandLine: " + str(Event["ParentCommandLine"]) + "\n"
                if "SourceIp" in Event and len(Event["SourceIp"]) != 0:
                    other = other + "Source IP Address: " + str(Event["SourceIp"]) + "\n"
                if "DestinationIp" in Event and len(Event["DestinationIp"]) != 0:
                    other = other + "Destionation IP Address: " + str(Event["DestinationIp"]) + "\n"
                if "OriginalFileName" in Event and len(Event["OriginalFileName"]) != 0:
                    other = other + "Original File Name: " + str(Event["OriginalFileName"]) + "\n"
                if "SubjectUserName" in Event and len(Event["SubjectUserName"]) != 0:
                    other = other + "Subject User Name: " + str(Event["SubjectUserName"]) + "\n"
                if "TargetUserName" in Event and len(Event["TargetUserName"]) != 0:
                    other = other + "Target User Name: " + str(Event["TargetUserName"]) + "\n"
                if "SubjectDomainName" in Event and len(Event["SubjectDomainName"]) != 0:
                    other = other + "Subject Domain Name: " + str(Event["SubjectDomainName"]) + "\n"
                if "Product" in Event and len(Event["Product"]) != 0:
                    other = other + "Product: " + str(Event["Product"]) + "\n"
                if "MD5" in Event and len(Event["MD5"]) != 0:
                    other = other + "MD5: " + str(Event["MD5"]) + "\n"
                if "SHA1" in Event and len(Event["SHA1"]) != 0:
                    other = other + "SHA1: " + str(Event["SHA1"]) + "\n"
                if "SHA256" in Event and len(Event["SHA256"]) != 0:
                    other = other + "SHA256: " + str(Event["SHA256"]) + "\n"
                if "IMPHASH" in Event and len(Event["IMPHASH"]) != 0:
                    other = other + "IMPHASH: " + str(Event["IMPHASH"]) + "\n"

                item1 = QStandardItem(str(Event['Timestamp']))
                item2 = QStandardItem(str(Event['EventID']))
                
                if "User" in Event and len(str(Event["User"])) != 0:
                    item3 = QStandardItem(str(Event['User']))
                elif "UserName" in Event and len(str(Event["UserName"])) != 0:
                    item3 = QStandardItem(str(Event['UserName']))
                else:
                    item3 = QStandardItem("")

                item4 = QStandardItem(other)
                item5 = QStandardItem(str(Event['RuleId']))

                self.model.appendRow([item1, item2, item3, item4, item5])
            
            self.tableView.resizeColumnsToContents()
            self.tableView.resizeRowsToContents()

            self.model_rule.setHorizontalHeaderLabels(["Count", "RuleName", "FalsePositives"])
            self.model.setHorizontalHeaderLabels(["DateTime", "EventID", "User", "Other", "RuleId"])
            self.label_3.setText(f"time = {milliseconds} ms")
        else:
            self.label_3.setText(f"error: no file or dir to check (evtx, csv)")

        IsAnalyzing = False

    def handle_table_click(self, index):
        # Handle click event for all rows
        row = index.row()
        column = index.column()
        item = self.model_rule.item(row, column)
        data = self.model_rule.index(row, 1).data() + self.model_rule.index(row, 2).data()[2:7]

        self.model_rule.setHorizontalHeaderLabels(["Count", "RuleName", "FalsePositives"])
        self.model.setHorizontalHeaderLabels(["DateTime", "EventID", "User", "Other", "RuleId"])
        self.proxy_model.setFilterRegExp(data)
        self.proxy_model.setFilterKeyColumn(4)
        result_count = self.proxy_model.rowCount()
        self.label_3.setText(f"Result Count: {result_count}")
        self.tableView.resizeColumnsToContents()
        self.tableView.resizeRowsToContents()

    def click_button_showall(self):
        self.proxy_model.setFilterRegExp("")
        self.proxy_model.setFilterKeyColumn(-1)
        result_count = self.proxy_model.rowCount()
        self.label_3.setText(f"Result Count: {result_count}")
        self.tableView.resizeColumnsToContents()
        self.tableView.resizeRowsToContents()

    def click_button_save(self):
        global Result_Event_list

        if len(Result_Event_list) == 0:
            return

        # Get the current datetime
        now = datetime.now()

        # Extracting keys
        all_keys = set()  # Using a set to avoid duplicates
        for entry in Result_Event_list:
            all_keys.update(entry.keys())

        new_keys = ["RuleName", "FalsePositives"]

        for key in all_keys:
            if key == "RuleName" or key == "FalsePositives":
                continue

            new_keys.append(key)

        # Create a new list with dictionaries having the desired key order
        new_json_array = [
            {key: entry[key] for key in new_keys} for entry in Result_Event_list
        ]

        # Format the datetime as a string
        datetime_str = now.strftime("%Y-%m-%d %H%M%S")

        # Specify the file name
        file_name = "result_" + datetime_str + ".csv"

        # Writing to CSV file
        with open(file_name, 'w', encoding='utf-8', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=new_keys)

            # Write the header
            writer.writeheader()

            # Write the data
            writer.writerows(new_json_array)

        print(f"JSON array has been written to {file_name}")

        self.show_notice()

    def show_notice(self):
        # Create a QMessageBox with an information role
        QMessageBox.information(self, 'Notice', 'The reuslts are saved successfully.')


    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "ThreadHound"))
        self.label.setText(_translate("Form", "Path: "))
        self.pushButton.setText(_translate("Form", "Open Dir"))
        self.pushButton_2.setText(_translate("Form", "Open File"))
        self.label_2.setText(_translate("Form", "Rule Dir Path:"))
        self.pushButton_4.setText(_translate("Form", "Open Dir"))
        self.pushButton_3.setText(_translate("Form", "Start"))
        self.label_3.setText(_translate("Form", "Status:"))
        self.label_4.setText(_translate("Form", ""))
        self.pushButton_save.setText(_translate("Form", "Save"))
        self.pushButton_showall.setText(_translate("Form", "Show All"))

    def show_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        fileDialog = QFileDialog()
        fileDialog.setFileMode(QFileDialog.ExistingFile)
        fileDialog.setNameFilter("Event Log Files (*.evtx);;CSV Files (*.csv)")

        file_name, _ = fileDialog.getOpenFileName(self, 'Open File', '', 'Event Log Files (*.evtx);;CSV Files (*.csv)', options=options)

        if os_type == "Windows":
            file_name = file_name.replace("/", "\\")

        if file_name:
            self.lineEdit.setText(file_name)
            print(f'Selected file: {file_name}')

    def show_folder_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        folder_dialog = QFileDialog()
        folder_dialog.setFileMode(QFileDialog.DirectoryOnly)

        folder_name = folder_dialog.getExistingDirectory(self, 'Open Folder', '', options=options)

        if os_type == "Windows":
            folder_name = folder_name.replace("/", "\\")

        if folder_name:
            self.lineEdit.setText(folder_name)
            print(f'Selected folder: {folder_name}')

    def show_folder_dialog_sigma(self):
        global IsSigmaLoaded
        IsSigmaLoaded = False

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        folder_dialog = QFileDialog()
        folder_dialog.setFileMode(QFileDialog.DirectoryOnly)

        folder_name = folder_dialog.getExistingDirectory(self, 'Open Folder', '', options=options)

        if os_type == "Windows":
            folder_name = folder_name.replace("/", "\\")

        if folder_name:
            self.lineEdit_2.setText(folder_name)
            print(f'Selected folder: {folder_name}')

            self.label_3.setText("Status: Loading sigma")

            GetRuleFilesList(folder_name)

            self.label_3.setText("Status: Load sigma Successfully!")
            IsSigmaLoaded = True

class Window(QMainWindow, Ui_Form):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        #self.connectSignalsSlots()

def main_form():
    app = QApplication(sys.argv)
    app.setStyleSheet(open('Combinear.qss').read())
    win = Window()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    # Initialize colorama
    init()

    LOGO()

    # Parse command-line arguments
    args = parse_arguments()

    sigma_manager.CheckUpdate()

    if args.form == True:
        main_form()
        pass
    elif args.path != None:
        rule_path = args.sigma

        if rule_path != None and len(rule_path) > 0:
            if os.path.exists(rule_path) and os.path.isdir(rule_path):
                pass
            else:
                print_colored("[-] error: rule path is incorrect.", Fore.RED)
                sys.exit(1)
        else:
            os_type = get_os_type()
            CurrentPath = os.getcwd()

            if os_type == "Windows":
                RulesDirectory = f"{CurrentPath}\\windows"
            else:
                RulesDirectory = f"{CurrentPath}/windows"

            rule_path = RulesDirectory

        GetRuleFilesList(rule_path)

        ui = Ui_Form()
        ui.main_func(args.path)

#original 104s
#sigma_manager multi 114s
#threathound.py multi 90s
#https://qss-stock.devsecstudio.com/templates.php
#pyuic5 -o main_window_ui.py ui/main_window.ui
#https://github.com/Yamato-Security/hayabusa