import os
import time
import yaml
import glob
from mappings import sigma_to_evtx_mapping, is_queryable
#from sigma.rule import SigmaYAMLLoader, SigmaRule

CurrentPath = os.getcwd()
SigmaPath = f"{CurrentPath}/sigma"
RulesDirectory = f"{CurrentPath}/windows"
RulesExist = os.path.exists(RulesDirectory)
RuleFilesList = []
Rules = []

#########################
#######rules array#######
#########################

#['C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\']
system_utility = []
action_reverse_shell = []

# Download Rules From Github Repo
#For me: the code is Linux focused 
def downloadRepo():
   github_repository_url = 'https://github.com/SigmaHQ/sigma.git'
   os.system(f'git clone {github_repository_url}')
   os.system(f'cp -r {SigmaPath}/rules/windows {CurrentPath}')
   os.system(f'rm -rf {SigmaPath}')

# Check Rules if Updated or Not
def CheckUpdate():
    # Check if Rules is Exist or Not
   if RulesExist == False:
      downloadRepo()
   else:
      # Check Rule Update
      DAY = 86400 # seconds -- POSIX day
      if (time.time() - os.path.getctime(RulesDirectory)) > DAY:
          os.system(f'rm -rf {RulesDirectory}')
          downloadRepo()
      else:
          print("Rules are Updated")

# Get all Rules From File Windows: Updates the Global variable
def GetRuleFilesList():
    for name in glob.glob(f'{RulesDirectory}/*.yml'):
       if name not in RuleFilesList:
        RuleFilesList.append(name)
    for name in glob.glob(f'{RulesDirectory}/*/*.yml'):
       if name not in RuleFilesList:
        RuleFilesList.append(name)
    for name in glob.glob(f'{RulesDirectory}/*/*/*.yml'):
       if name not in RuleFilesList:
        RuleFilesList.append(name)

def SigmaRulesParse(Rule):
    print("test")

def MatchRules(Event):
    matched_rules = list()
    loader = True
    event_count = 1
    print("Scanning the logs: [\]\r", end=" ")
    for RuleName in RuleFilesList:
        if loader:
            print(f"Checked event against rule: {event_count}, Scanning the logs: [/]    \r", end=" ")
            loader = False
        else:
            print(f"Checked event against rule: {event_count}, Scanning the logs: [\]    \r", end=" ")
            loader = True
        try:
            with open(RuleName, 'r') as Rulefile:
                RuleObject = yaml.safe_load(Rulefile)
                if len(Event["EventID"]) > 0:
                    if is_queryable(RuleObject["logsource"], Event["EventID"]):
                        detection_fields = RuleObject["detection"].keys()
                        overall_match = dict() # dict that contains matches against each selections
                        
                        for detection_field in detection_fields:
                            if "condition" == detection_field: # condition
                                condition_list = RuleObject["detection"][detection_field].split()
                                # convert raw fields to their boolean outcome
                                for condition_item in range(0,len(condition_list)):
                                    if condition_list[condition_item] in overall_match.keys():
                                        condition_list[condition_item] = overall_match[condition_list[condition_item]]
                                # convert x of filed* to their boolean outcome
                                for condition_item in range(0,len(condition_list)):
                                    if condition_list[condition_item] in ["1","2","3","4","5","6","7","8","9","10"]:
                                        required_length = int(condition_list[condition_item])
                                        selection_name = condition_list[condition_item+2].replace("*","")
                                        result = list()
                                        for key in overall_match.keys():
                                            if key.startswith(selection_name) and overall_match[key]:
                                                result.append(overall_match[key])
                                        if required_length == len(result):
                                            condition_list[condition_item+2] = True
                                        else:
                                            condition_list[condition_item+2] = False
                                        condition_list.pop(condition_item)
                                        condition_list.pop(condition_item)
                                        if condition_item >= len(condition_list)-1:
                                            break
                                    if condition_list[condition_item] == "all":
                                        selection_name = condition_list[condition_item+2].replace("*","")
                                        result = list()
                                        for key in overall_match.keys():
                                            if key.startswith(selection_name):
                                                result.append(overall_match[key])
                                        if False in result:
                                            condition_list[condition_item+2] = False
                                        else:
                                            condition_list[condition_item+2] = True
                                        condition_list.pop(condition_item)
                                        condition_list.pop(condition_item)
                                        if condition_item >= len(condition_list)-1:
                                            break
                                evaluation_string = ""
                                for condition in condition_list:
                                    if isinstance(condition,bool):
                                        if condition:
                                            evaluation_string+="True "
                                        if not condition:
                                            evaluation_string+="False "
                                    elif condition == "and" or condition == "&":
                                        evaluation_string+="and "
                                    elif condition == "or" or condition == "|":
                                        evaluation_string+="or "
                                    elif condition == "not":
                                        evaluation_string+="not "
                                    elif condition == "(":
                                        evaluation_string+="("
                                    elif condition == ")":
                                        evaluation_string+=")"
                                if eval(evaluation_string):
                                    matched_rules.append(RuleObject)
                                else:
                                    pass

                            else: # selection and filter content
                                if isinstance(RuleObject["detection"][detection_field], dict):
                                    selection_fields = RuleObject["detection"][detection_field].keys()
                                elif isinstance(RuleObject["detection"][detection_field], list):
                                    #
                                    # this exception needs to be handled in future a it does not allow running SIGMA rule
                                    #
                                    overall_match[detection_field] = False
                                    break
                                
                                selection_field_match_list = list()

                                for selection_field in selection_fields:
                                    selection_object_match_list = list() # list that contains matches against each objects in a selection_field which will be ORed
                                    fieldname = selection_field.split("|")[0]
                                    
                                    if fieldname not in Event:
                                        #
                                        # this exception needs to be handled in future a it does not allow running SIGMA rule
                                        #
                                        print(fieldname+" field not parsed, skipping from the rule")
                                        selection_object_match_list.append(1)
                                        break
                                    if "#" in selection_field: #ignore the commented lines in the SIGMA rule
                                        continue
                                    
                                    if "startswith" in selection_field: # startswith routine
                                        if len(Event[fieldname]) == 0:
                                            selection_object_match_list.append(0)
                                        else:
                                            if isinstance(RuleObject["detection"][detection_field][selection_field], list):
                                                for value in RuleObject["detection"][detection_field][selection_field]:
                                                    if Event[fieldname].startswith(value):
                                                        selection_object_match_list.append(1)
                                                    else:
                                                        selection_object_match_list.append(0)
                                            else:
                                                if Event[fieldname].startswith(RuleObject["detection"][detection_field][selection_field]):
                                                    selection_object_match_list.append(1)
                                                else:
                                                    selection_object_match_list.append(0)
                                        if 1 in selection_object_match_list:
                                            selection_field_match_list.append(1)
                                        else:
                                            selection_field_match_list.append(0)
                                    
                                    elif "endswith" in selection_field: # endsswith routine
                                        if len(Event[fieldname]) == 0:
                                            selection_object_match_list.append(0)
                                        else:
                                            if isinstance(RuleObject["detection"][detection_field][selection_field], list):
                                                for value in RuleObject["detection"][detection_field][selection_field]:
                                                    if Event[fieldname].endswith(value):
                                                        selection_object_match_list.append(1)
                                                    else:
                                                        selection_object_match_list.append(0)
                                            else:
                                                if Event[fieldname].endswith(RuleObject["detection"][detection_field][selection_field]):
                                                    selection_object_match_list.append(1)
                                                else:
                                                    selection_object_match_list.append(0)
                                        if 1 in selection_object_match_list:
                                            selection_field_match_list.append(1)
                                        else:
                                            selection_field_match_list.append(0)

                                    elif "contains|all" in selection_field: # contians routine
                                        if len(Event[fieldname]) == 0:
                                            selection_object_match_list.append(0)
                                        else:
                                            if isinstance(RuleObject["detection"][detection_field][selection_field], list):
                                                for value in RuleObject["detection"][detection_field][selection_field]:
                                                    if value in Event[fieldname]:
                                                        selection_object_match_list.append(1)
                                                    else:
                                                        selection_object_match_list.append(0)
                                            else:
                                                if RuleObject["detection"][detection_field][selection_field] in Event[fieldname]:
                                                    selection_object_match_list.append(1)
                                                else:
                                                    selection_object_match_list.append(0)
                                        if 0 in selection_object_match_list:
                                            selection_field_match_list.append(0)
                                        else:
                                            selection_field_match_list.append(1)
                                    
                                    elif "contains" in selection_field: # contians routine
                                        if len(Event[fieldname]) == 0:
                                            selection_object_match_list.append(0)
                                        else: 
                                            if isinstance(RuleObject["detection"][detection_field][selection_field], list):
                                                for value in RuleObject["detection"][detection_field][selection_field]:
                                                    if value in Event[fieldname]:
                                                        selection_object_match_list.append(1)
                                                    else:
                                                        selection_object_match_list.append(0)
                                            else:
                                                if RuleObject["detection"][detection_field][selection_field] in Event[fieldname]:
                                                    selection_object_match_list.append(1)
                                                else:
                                                    selection_object_match_list.append(0)
                                        if 1 in selection_object_match_list:
                                            selection_field_match_list.append(1)
                                        else:
                                            selection_field_match_list.append(0)

                                    else: # exact match routine
                                        if len(Event[fieldname]) == 0:
                                            selection_object_match_list.append(0)
                                        else:
                                            if isinstance(RuleObject["detection"][detection_field][selection_field], list):
                                                for value in RuleObject["detection"][detection_field][selection_field]:
                                                    if Event[fieldname] == value:
                                                        selection_object_match_list.append(1)
                                                    else:
                                                        selection_object_match_list.append(0)
                                            else:
                                                if Event[fieldname] == RuleObject["detection"][detection_field][selection_field]:
                                                    selection_object_match_list.append(1)
                                                else:
                                                    selection_object_match_list.append(0)
                                        if 1 in selection_object_match_list:
                                            selection_field_match_list.append(1)
                                        else:
                                            selection_field_match_list.append(0)
                                if 0 in selection_field_match_list:
                                    overall_match[detection_field] = False
                                else:
                                    overall_match[detection_field] = True
                    
                    else:
                        pass
        except Exception as ERROR:
            # print(f"Skipping the rule rule: {RuleName}")
            # print(ERROR)
            pass # Silently skip the rules with obsolete conditions
        event_count+=1
    return matched_rules

GetRuleFilesList()


