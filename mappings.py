# this is a refernce set of the fields in Event Logs
sigma_to_evtx_mapping = {
  "timestamp": "Event.System.TimeCreated",
  "EventID" : "Event.System.EventID",
  # "EventRecordID" : "Event.System.EventRecordID",
  "Computer" : "Event.System.Computer",
  # "EventData" : "Event.EventData",
  # "AccessList" : "Event.EventData.AccessList",
  "AccessMask" : "Event.EventData.AccessMask",
  # "Accesses" : "Event.EventData.Accesses",
  "AccountName" : "Event.EventData.AccountName",
  "Action" : "Event.EventData.Action",
  # "Address" : "Event.EventData.Address",
  # "AllowedToDelegateTo" : "Event.EventData.AllowedToDelegateTo",
  # "Application" : "Event.EventData.Application",
  # "ApplicationPath" : "Event.EventData.ApplicationPath",
  # "AttributeLDAPDisplayName" : "Event.EventData.AttributeLDAPDisplayName",
  # "AttributeValue" : "Event.EventData.AttributeValue",
  "AuditPolicyChanges" : "Event.EventData.AuditPolicyChanges",
  # "AuditSourceName" : "Event.EventData.AuditSourceName",
  # "AuthenticationPackageName" : "Event.EventData.AuthenticationPackageName",
  "CallTrace" : "Event.EventData.CallTrace",
  "CallerProcessName" : "Event.EventData.CallerProcessName",
  # "Caption" : "Event.EventData.Caption",
  # "CertThumbprint" : "Event.EventData.CertThumbprint",
  "Channel" : "Event.System.Channel",
  "ClassName" : "Event.EventData.ClassName",
  "CommandLine" : "Event.EventData.CommandLine",
  "Company" : "Event.EventData.Company",
  "ContextInfo" : "Event.EventData.ContextInfo",
  "CurrentDirectory" : "Event.EventData.CurrentDirectory",
  "Description" : "Event.EventData.Description",
  # "DestAddress" : "Event.EventData.DestAddress",
  # "DestPort" : "Event.EventData.DestPort",
  # "Destination" : "Event.EventData.Destination",
  "DestinationHostname" : "Event.EventData.DestinationHostname",
  "DestinationIp" : "Event.EventData.DestinationIp",
  "DestinationIsIpv6" : "Event.EventData.DestinationIsIpv6",
  "DestinationPort" : "Event.EventData.DestinationPort",
  "Details" : "Event.EventData.Details",
  # "Device" : "Event.EventData.Device",
  # "DeviceDescription" : "Event.EventData.DeviceDescription",
  # "DeviceName" : "Event.EventData.DeviceName",
  "EngineVersion" : "Event.EventData.EngineVersion",
  # "ErrorCode" : "Event.EventData.ErrorCode",
  # "EventType" : "Event.EventData.EventType",
  # "FailureCode" : "Event.EventData.FailureCode",
  "FileName" : "Event.EventData.FileName",
  "FileVersion" : "Event.EventData.FileVersion",
  "GrantedAccess" : "Event.EventData.GrantedAccess",
  "GrandparentCommandLine" : "Event.EventData.GrandparentCommandLine",
  "Hashes" : "Event.EventData.Hashes",
  # "HiveName" : "Event.EventData.HiveName",
  "HostApplication" : "Event.EventData.HostApplication",
  # "HostName" : "Event.EventData.HostName",
  # "HostVersion" : "Event.EventData.HostVersion",
  "Image" : "Event.EventData.Image",
  "ImageFileName" : "Event.EventData.ImageFileName",
  "ImageLoaded" : "Event.EventData.ImageLoaded",
  "ImagePath" : "Event.EventData.ImagePath",
  "Imphash" : "Event.EventData.Imphash",
  "Initiated" : "Event.EventData.Initiated",
  "IntegrityLevel" : "Event.EventData.IntegrityLevel",
  "IpAddress" : "Event.EventData.IpAddress",
  "KeyLength" : "Event.EventData.KeyLength",
  # "Keywords" : "Event.System.Keywords",
  # "LayerRTID" : "Event.EventData.LayerRTID",
  # "Level" : "Event.System.Level",
  # "LocalName" : "Event.EventData.LocalName",
  # "LogonId" : "Event.EventData.LogonId",
  "LogonProcessName" : "Event.EventData.LogonProcessName",
  "LogonType" : "Event.EventData.LogonType",
  # "Message" : "Event.EventData.Message",
  # "ModifyingApplication" : "Event.EventData.ModifyingApplication",
  # "NewName" : "Event.EventData.NewName",
  "NewTargetUserName" : "Event.EventData.NewTargetUserName",
  # "NewTemplateContent" : "Event.EventData.NewTemplateContent",
  # "NewUacValue" : "Event.EventData.NewUacValue",
  # "NewValue" : "Event.EventData.NewValue",
  # "ObjectClass" : "Event.EventData.ObjectClass",
  "ObjectName" : "Event.EventData.ObjectName",
  "ObjectServer" : "Event.EventData.ObjectServer",
  "ObjectType" : "Event.EventData.ObjectType",
  # "ObjectValueName" : "Event.EventData.ObjectValueName",
  "OldTargetUserName" : "Event.EventData.OldTargetUserName",
  # "OldUacValue" : "Event.EventData.OldUacValue",
  # "Origin" : "Event.EventData.Origin",
  "OriginalFileName" : "Event.EventData.OriginalFileName",
  # "OriginalName" : "Event.EventData.OriginalName",
  "ParentCommandLine" : "Event.EventData.ParentCommandLine",
  "ParentImage" : "Event.EventData.ParentImage",
  # "ParentUser" : "Event.EventData.ParentUser",
  # "PasswordLastSet" : "Event.EventData.PasswordLastSet",
  "Path" : "Event.EventData.Path",
  "Payload" : "Event.EventData.Payload",
  "PipeName" : "Event.EventData.PipeName",
  # "PossibleCause" : "Event.EventData.PossibleCause",
  # "PrivilegeList" : "Event.EventData.PrivilegeList",
  "ProcessId" : "Event.EventData.ProcessId",
  # "ProcessName" : "Event.EventData.ProcessName",
  "Product" : "Event.EventData.Product",
  # "Properties" : "Event.EventData.Properties",
  # "Protocol" : "Event.EventData.Protocol",
  # "Provider" : "Event.System.Provider",
  "ProviderName" : "Event.EventData.ProviderName",
  "Provider_Name" : "Event.EventData.Provider_Name",
  # "QNAME" : "Event.EventData.QNAME",
  # "Query" : "Event.EventData.Query",
  # "QueryName" : "Event.EventData.QueryName",
  # "QueryResults" : "Event.EventData.QueryResults",
  # "QueryStatus" : "Event.EventData.QueryStatus",
  "RelativeTargetName" : "Event.EventData.RelativeTargetName",
  # "RemoteAddress" : "Event.EventData.RemoteAddress",
  # "RemoteName" : "Event.EventData.RemoteName",
  "SamAccountName" : "Event.EventData.SamAccountName",
  "ScriptBlockText" : "Event.EventData.ScriptBlockText",
  # "SearchFilter" : "Event.EventData.SearchFilter",
  # "ServerName" : "Event.EventData.ServerName",
  # "Service" : "Event.EventData.Service",
  # "ServiceFileName" : "Event.EventData.ServiceFileName",
  "ServiceName" : "Event.EventData.ServiceName",
  "ServicePrincipalNames" : "Event.EventData.ServicePrincipalNames",
  "ServiceStartType" : "Event.EventData.ServiceStartType",
  "ServiceType" : "Event.EventData.ServiceType",
  "ShareName" : "Event.EventData.ShareName",
  # "SidHistory" : "Event.EventData.SidHistory",
  "Signed" : "Event.EventData.Signed",
  # "SourceAddress" : "Event.EventData.SourceAddress",
  "SourceImage" : "Event.EventData.SourceImage",
  "SourceIp" : "Event.EventData.SourceIp",
  "SourcePort" : "Event.EventData.SourcePort",
  "Source_Name" : "Event.EventData.Source_Name",
  # "StartAddress" : "Event.EventData.StartAddress",
  "StartFunction" : "Event.EventData.StartFunction",
  "StartModule" : "Event.EventData.StartModule",
  "State" : "Event.EventData.State",
  "Status" : "Event.EventData.Status",
  "SubjectDomainName" : "Event.EventData.SubjectDomainName",
  # "SubjectLogonId" : "Event.EventData.SubjectLogonId",
  "SubjectUserName" : "Event.EventData.SubjectUserName",
  "SubjectUserSid" : "Event.EventData.SubjectUserSid",
  # "TargetFilename" : "Event.EventData.TargetFilename",
  "TargetImage" : "Event.EventData.TargetImage",
  # "TargetLogonId" : "Event.EventData.TargetLogonId",
  # "TargetName" : "Event.EventData.TargetName",
  "TargetObject" : "Event.EventData.TargetObject",
  # "TargetParentProcessId" : "Event.EventData.TargetParentProcessId",
  # "TargetPort" : "Event.EventData.TargetPort",
  # "TargetServerName" : "Event.EventData.TargetServerName",
  # "TargetSid" : "Event.EventData.TargetSid",
  "TargetUserName" : "Event.EventData.TargetUserName",
  "TargetUserSid" : "Event.EventData.TargetUserSid",
  "TaskName" : "Event.EventData.TaskName",
  # "TemplateContent" : "Event.EventData.TemplateContent",
  "TicketEncryptionType" : "Event.EventData.TicketEncryptionType",
  "TicketOptions" : "Event.EventData.TicketOptions",
  # "Type" : "Event.EventData.Type",
  "User" : "Event.EventData.User",
  "UserName" : "Event.EventData.UserName",
  # "Value" : "Event.EventData.Value",
  # "Workstation" : "Event.EventData.Workstation",
  "WorkstationName" : "Event.EventData.WorkstationName",
  # "param1" : "Event.EventData.param1",
  # "param2" : "Event.EventData.param2",
  # "processPath" : "Event.EventData.processPath",
  "sha1" : "Event.EventData.sha1"
}

# this logsource_mapping is to tell the sigma_manager which rule would run against which event
# fundamentally, all sigma rules can not run on all events because they will generate FP Noise and waste so much resources
# SIGMA rules will run only on mapped Events, For example
# if you add mapping for a process_creation in EventID of Sysmon Event 1, then you should add 4688 also to support corresponding Windows Logs as well

logsource_mapping = {
  "windows": {
    "None" : {
      "None" : {
        "EventID" : ["*"], # "*" tells the sigma manager to run against all kinds of Events
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_remote_thread" : {
        "EventID" : ["8"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_stream_hash" : {
        "EventID" : ["15"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "dns_query" : {
        "EventID" : ["22"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "driver_load" : {
        "EventID" : ["6"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "image_load" : {
        "EventID" : ["7"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "network_connection" : {
        "EventID" : ["3"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "pipe_created" : {
        "EventID" : ["17","18","5145"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_access" : {
        "EventID" : ["10"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_creation" : {
        "EventID" : ["1","4688"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "raw_access_thread" : {
        "EventID" : ["9"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_error" : {
        "EventID" : ["255"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_status" : {
        "EventID" : ["4","16"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "file_block" : {
        "EventID" : ["27"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_tampering" : {
        "EventID" : ["25"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "wmi_event" : {
        "EventID" : ["19","20","21"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "registry_event" : {
        "EventID" : ["12","13","14","4657"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_module" : {
        "EventID" : ["4103"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_script" : {
        "EventID" : ["4104"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_start" : {
        "EventID" : ["400"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_provider_start" : {
        "EventID" : ["600"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_script" : {
        "EventID" : ["800"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      }
    },
    "sysmon" : {
      "None" : {
        "EventID" : ["*"], # "*" tells the sigma manager to run against all kinds of Events
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_remote_thread" : {
        "EventID" : ["8"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_stream_hash" : {
        "EventID" : ["15"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "dns_query" : {
        "EventID" : ["22"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "driver_load" : {
        "EventID" : ["6"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "image_load" : {
        "EventID" : ["7"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "network_connection" : {
        "EventID" : ["3"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "pipe_created" : {
        "EventID" : ["17","18","5145"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_access" : {
        "EventID" : ["10"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_creation" : {
        "EventID" : ["1","4688"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "raw_access_thread" : {
        "EventID" : ["9"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_error" : {
        "EventID" : ["255"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_status" : {
        "EventID" : ["4","16"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "file_block" : {
        "EventID" : ["27"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_tampering" : {
        "EventID" : ["25"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "wmi_event" : {
        "EventID" : ["19","20","21"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "registry_event" : {
        "EventID" : ["12","13","14","4657"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_module" : {
        "EventID" : ["4103"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_script" : {
        "EventID" : ["4104"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_start" : {
        "EventID" : ["400"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_provider_start" : {
        "EventID" : ["600"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_script" : {
        "EventID" : ["800"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      }
    },
    "security" : {
      "None" : {
        "EventID" : ["*"], # "*" tells the sigma manager to run against all kinds of Events
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_remote_thread" : {
        "EventID" : ["8"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "create_stream_hash" : {
        "EventID" : ["15"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "dns_query" : {
        "EventID" : ["22"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "driver_load" : {
        "EventID" : ["6"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "image_load" : {
        "EventID" : ["7"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "network_connection" : {
        "EventID" : ["3"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "pipe_created" : {
        "EventID" : ["17","18","5145"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_access" : {
        "EventID" : ["10"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_creation" : {
        "EventID" : ["1","4688"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "raw_access_thread" : {
        "EventID" : ["9"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_error" : {
        "EventID" : ["255"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "sysmon_status" : {
        "EventID" : ["4","16"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "file_block" : {
        "EventID" : ["27"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "process_tampering" : {
        "EventID" : ["25"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "wmi_event" : {
        "EventID" : ["19","20","21"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"]
      },
      "registry_event" : {
        "EventID" : ["12","13","14","4657"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_module" : {
        "EventID" : ["4103"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_script" : {
        "EventID" : ["4104"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_start" : {
        "EventID" : ["400"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_provider_start" : {
        "EventID" : ["600"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      },
      "ps_classic_script" : {
        "EventID" : ["800"],
        "Channels" : [
          "Microsoft-Windows-Sysmon/Operational",
          "Security"
        ]
      }
    }
  } 
}

def is_queryable(Logsource, EventID):
  # Sanity check

  if "product" not in Logsource:
    print("Invalid Rule without logsource product encountered")
    pass
  if "category" not in Logsource:
    Logsource["category"] = "None"
  if "service" not in Logsource:
    Logsource["service"] = "None"
  if "source" not in Logsource:
    Logsource["source"] = "None"

  if (
    EventID in logsource_mapping[Logsource["product"]][Logsource["service"]][Logsource["category"]]["EventID"] or 
    logsource_mapping[Logsource["product"]][Logsource["service"]][Logsource["category"]]["EventID"] == "*"
    ):
    return True
  else:
    return False