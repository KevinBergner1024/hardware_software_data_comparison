import argparse
import textwrap
import pathlib
import pandas as pd
import xml.etree.ElementTree as ET
import datetime
import progressbar
import os

NAME = "Process Windows Audit Logs Script"
VERSION = "1.5"
CMD_MODE_ENABLED = False
WAL_DEFAULT_TAG_APPENDIX = "{http://schemas.microsoft.com/win/2004/08/events/event}"
WAL_SYSTEM_EVENT_DATA_TEMPLATE = {"SYSTEM_Provider_NAME": None, "SYSTEM_Provider_Guid": None, "SYSTEM_EventID": None,"SYSTEM_Version": None, "SYSTEM_Level": None, "SYSTEM_Task": None,
                                    "SYSTEM_Opcode": None, "SYSTEM_Keywords": None, "SYSTEM_TimeCreated": None, "SYSTEM_EventRecordID": None, "SYSTEM_Correlation": None,
                                    "SYSTEM_Execution_ProcessID": None,"SYSTEM_Execution_ThreadID": None, "SYSTEM_Channel": None, "SYSTEM_Computer": None,"SYSTEM_Security": None}

def parse_xml_converted_windows_audit_logs(file_path:pathlib.Path, default_windows_audit_logs_system_event_data_template:dict=WAL_SYSTEM_EVENT_DATA_TEMPLATE, timezone:str="CET", quality_check_fast_mode_enabled:bool=False):
    """parse windows audit logs in dataframe

    Args:
        file_path (pathlib.Path): system path to windows audit log file in xml format
        default_windows_audit_logs_system_event_data_template (dict): template for event system data. Defaults to WAL_SYSTEM_EVENT_DATA_TEMPLATE.
        timezone (str): timezone to convert parsed Windows security file to (UTC -> timezone). Defaults to "CET".
        quality_check_fast_mode_enabled (bool): apply fast mode by only using 4663 events with corresponding features for parsed dataframe. Defaults to False.

    Raises:
        TypeError: raises error file given path does not refer to a file

    Returns:
        pd.DataFrame: dataframe which contains parsed windows audit log data
    """
    try:
        if(file_path.is_file()):
            xml_tree = ET.parse(file_path)
            xml_tree_root = xml_tree.getroot()
            windows_audit_logs_system_data_rows = []
            windows_audit_logs_event_data_rows = []
            for windows_audit_logs__security_event in xml_tree_root:
                if(windows_audit_logs__security_event[0][0].attrib['Name'] == 'Microsoft-Windows-Security-Auditing'):
                    for system_or_event_data in windows_audit_logs__security_event:
                        if(system_or_event_data.tag.replace(WAL_DEFAULT_TAG_APPENDIX, "") == "System"):
                            system_event_data_template = default_windows_audit_logs_system_event_data_template.copy()
                            for element in system_or_event_data:
                                if(element.tag == (WAL_DEFAULT_TAG_APPENDIX + "Provider")):
                                    system_event_data_template['SYSTEM_Provider_NAME'] = element.attrib['Name']
                                    system_event_data_template['SYSTEM_Provider_Guid'] = element.attrib['Guid']
                                elif(element.tag == (WAL_DEFAULT_TAG_APPENDIX + "TimeCreated")):
                                    system_event_data_template['SYSTEM_TimeCreated'] = element.attrib['SystemTime']
                                elif(element.tag == (WAL_DEFAULT_TAG_APPENDIX + "Execution")):
                                    system_event_data_template['SYSTEM_ProcessID'] = system_or_event_data.find(element.tag).attrib['ProcessID']
                                    system_event_data_template['SYSTEM_ThreadID'] = element.attrib['ThreadID']
                                else:
                                    dict_key = 'SYSTEM_' + (element.tag.replace(WAL_DEFAULT_TAG_APPENDIX, ""))
                                    system_event_data_template[dict_key] = element.text
                            windows_audit_logs_system_data_rows.append(system_event_data_template)

                        elif(system_or_event_data.tag.replace(WAL_DEFAULT_TAG_APPENDIX, "") == "EventData"):
                            audit_log_eventdata_dict_template = {}
                            for element in system_or_event_data:
                                feature_string = 'EVENTDATA' + '_' + element.attrib['Name']
                                audit_log_eventdata_dict_template[feature_string] = element.text
                            windows_audit_logs_event_data_rows.append(audit_log_eventdata_dict_template)

            dataframe_system_audit_logs = pd.DataFrame(windows_audit_logs_system_data_rows)
            dataframe_eventdata_audit_logs = pd.DataFrame(windows_audit_logs_event_data_rows)
            # parse to datetime format and remove time zone information & convert from UTC to CET/ CEST time format
            dataframe_system_audit_logs["SYSTEM_TimeCreated"] = pd.to_datetime(dataframe_system_audit_logs["SYSTEM_TimeCreated"]).dt.tz_localize(None)
            if(timezone == "CET"):
                # convert time zone from UTC to CET
                dataframe_system_audit_logs['SYSTEM_TimeCreated'] = dataframe_system_audit_logs['SYSTEM_TimeCreated'] + pd.Timedelta(hours=1)
            elif(timezone == "CEST"):
                # convert time zone from UTC to CEST
                dataframe_system_audit_logs['SYSTEM_TimeCreated'] = dataframe_system_audit_logs['SYSTEM_TimeCreated'] + pd.Timedelta(hours=2)
            
        else:
            raise TypeError
    except TypeError:
        print("TypeError: method parameter is not a file")
    
    return_dataframe = pd.concat([dataframe_system_audit_logs,dataframe_eventdata_audit_logs], axis=1).sort_values(by="SYSTEM_TimeCreated", ignore_index=True)
    # only 4663 events for quality checks needed
    if(quality_check_fast_mode_enabled):
        return return_dataframe.loc[return_dataframe['SYSTEM_EventID'] == "4663"]
    else:
        return return_dataframe

def load_windows_audit_logs_from_system_folder(folder_path:pathlib.Path, timestamp_col_name_windows_audit_logs:str="SYSTEM_TimeCreated", remove_linux_wal_converter_artefacts:bool=False, timezone_of_simulation_run:str="CET", quality_check_fast_mode_enabled:bool=False):
    """load windows audit logs from folder into dataframe container

    Args:
        folder_path (pathlib.Path): path to folder which contains windows audit logs in XML format
        timestamp_col_name_windows_audit_logs (str, optional): dataframe column name to sort parsed windows audit logs. Defaults to "SYSTEM_TimeCreated".
        remove_linux_wal_converter_artefacts (bool, optional): remove linux converter tool artefacts at the beginning of the file & add general XML structure tags for completeness. Defaults to False.
        timezone_of_simulation_run (str): timezone which should be used for simulation run. Defaults to "CET".
        quality_check_fast_mode_enabled (bool): apply fast mode by only using 4663 events with corresponding features for parsed dataframe. Defaults to False.

    Returns:
        pd.DataFrame: dataframe which contains xml parsed windows audit logs files
    """
    concat_audit_logs_df = pd.DataFrame()
    folder_content = os.listdir(folder_path)
    length = len([file_name for file_name in folder_content if ("Archive-Security" in file_name)])
    counter = 0
    with progressbar.ProgressBar(max_value=length) as bar:
        bar.update(counter)
        for sub_path in folder_path.iterdir():
            if((sub_path.is_file()) & ("Archive-Security" in str(sub_path))):
                if(remove_linux_wal_converter_artefacts):
                    '''
                    NEEDS TO BE REMOVED LATER
                    linux_content = sub_path.read_text()
                    # remove linux converter artefacts -> create embedding for parsing
                    linux_content = linux_content[21:]
                    file_content = '<?xml version="1.0" encoding="utf-8" standalone="yes"?><Events>' + linux_content +'</Events>'
                    sub_path.write_text(file_content)
                    '''
                parsed_audit_logs = parse_xml_converted_windows_audit_logs(file_path=sub_path, timezone=timezone_of_simulation_run, quality_check_fast_mode_enabled=quality_check_fast_mode_enabled)
                frames = [concat_audit_logs_df, parsed_audit_logs]
                concat_audit_logs_df = pd.concat(frames, copy=False, ignore_index=True, axis=0)
                concat_audit_logs_df = concat_audit_logs_df.sort_values(by=timestamp_col_name_windows_audit_logs, ignore_index=True)
                counter = counter + 1
            bar.update(counter)
    
    return concat_audit_logs_df

def load_windows_audit_logs_from_system_file(file_path:pathlib.Path, timestamp_col_name_windows_audit_logs:str="SYSTEM_TimeCreated", remove_linux_wal_converter_artefacts:bool=False, timezone_of_simulation_run:str="CET", quality_check_fast_mode_enabled:bool=False):
    """load windows audit logs from file into dataframe container

    Args:
        file_path (pathlib.Path): path to file which contains windows audit log in XML format
        timestamp_col_name_windows_audit_logs (str, optional): dataframe column name to sort parsed windows audit logs. Defaults to "SYSTEM_TimeCreated".
        remove_linux_wal_converter_artefacts (bool, optional): remove linux converter tool artefacts at the beginning of the file & add general XML structure tags for completeness. Defaults to False.
        timezone_of_simulation_run (str, optional): timezone which should be used for simulation run. Defaults to "CET".
        quality_check_fast_mode_enabled (bool): apply fast mode by only using 4663 events with corresponding features for parsed dataframe. Defaults to False.

    Returns:
        pd.DataFrame: dataframe which contains xml parsed windows audit logs file
    """
    counter = 0
    with progressbar.ProgressBar(max_value=1) as bar:
        bar.update(counter)
        if((os.path.isfile(file_path)) & ("Archive-Security" in str(file_path))):
            if(remove_linux_wal_converter_artefacts):
                '''
                linux_content = sub_path.read_text()
                # remove linux converter artefacts -> create embedding for parsing
                linux_content = linux_content[21:]
                file_content = '<?xml version="1.0" encoding="utf-8" standalone="yes"?><Events>' + linux_content +'</Events>'
                sub_path.write_text(file_content)
                '''
            parsed_audit_logs = parse_xml_converted_windows_audit_logs(file_path=file_path, timezone=timezone_of_simulation_run, quality_check_fast_mode_enabled=quality_check_fast_mode_enabled).sort_values(by=timestamp_col_name_windows_audit_logs, ignore_index=True)
            counter = counter + 1
            bar.update(counter)
    
    return parsed_audit_logs


def attach_sim_23_logs_labels_col_windows_audit_logs(audit_logs_df:pd.DataFrame, sim23_logs:list, timestamp_col_name_windows_audit_logs:str="SYSTEM_TimeCreated", labeling_col_name:str="Labels"):
    """label converted windows audit logs based on sim23.log bot behavior (programming, mailing, encrypt attack(copy, encrypt, decrypt, delete), mutillidae, chatting, copyfiles, peertube)

    Args:
        audit_logs_df (pd.DataFrame): windows audit logs dataframe to label
        sim23_logs (list): list of convertet sim23.log entries
        timestamp_col_name_windows_audit_logs (str, optional): windows audit logs feature name for event creation timestamp. Defaults to "SYSTEM_TimeCreated".
        labeling_col_name (str, optional): windows audit logs dataframe column name to label rows. Defaults to "Labels".

    Returns:
        pd.DataFrame: dataframe containing labeled bot behavior
    """
    # double check later if the df.copy command blews up the RAM
    copy = audit_logs_df.copy()
    copy[labeling_col_name] = 'no_label'
    for row_entry in sim23_logs:
        # pre-defined indices from method: self.parse_cidds_local_instance_logs()
        local_instance_logs_start_time = row_entry[0]
        local_instance_logs_end_time = row_entry[1]
        local_instance_logs_behavior_label = row_entry[2]
        # data with no specific behavior label will not be used for further evaluation
        copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= local_instance_logs_behavior_label
    
    return copy
    #return copy[copy[labeling_col_name] != 'no_label']

def attach_sim_23_logs_labels_col_windows_audit_logs_general_behavior_level(audit_logs_df:pd.DataFrame, sim23_logs:list, timestamp_col_name_windows_audit_logs:str="SYSTEM_TimeCreated", labeling_col_name:str="group_label"):
    """label converted windows audit logs based on sim23.log bot behavior (programming, mailing, encrypt attack(copy, encrypt, decrypt, delete), mutillidae, chatting, copyfiles, peertube)

    Args:
        audit_logs_df (pd.DataFrame): windows audit logs dataframe to label
        sim23_logs (list): list of convertet sim23.log entries
        timestamp_col_name_windows_audit_logs (str, optional): windows audit logs feature name for event creation timestamp. Defaults to "SYSTEM_TimeCreated".
        labeling_col_name (str, optional): windows audit logs dataframe column name to label rows. Defaults to "Labels".

    Returns:
        pd.DataFrame: dataframe containing labeled bot behavior
    """
    # double check later if the df.copy command blews up the RAM
    copy = audit_logs_df.copy()
    copy[labeling_col_name] = 'default_label'
    for row_entry in sim23_logs:
        # pre-defined indices from method: self.parse_cidds_local_instance_logs()
        local_instance_logs_start_time = row_entry[0]
        local_instance_logs_end_time = row_entry[1]
        local_instance_logs_behavior_label = row_entry[2]
        if("copy" in local_instance_logs_behavior_label):
        # data with no specific behavior label will not be used for further evaluation
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'copy'
        elif("peertube" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'peertube'
        elif("programming" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'programming'
        elif("chatting" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'chatting'
        elif("mailing" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'mailing'
        elif("mutillidae" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'mutillidae'
        elif("encrypt" in local_instance_logs_behavior_label):
            copy.loc[((copy[timestamp_col_name_windows_audit_logs] >= local_instance_logs_start_time) & (copy[timestamp_col_name_windows_audit_logs] <= local_instance_logs_end_time)), labeling_col_name]= 'encrypt_attack'

    return copy[copy[labeling_col_name] != 'default_label']

def main():
    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog=NAME,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent(('''
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage:
        ''')%(NAME, VERSION)))
        
        return_code = main()
        quit(return_code)
    else:
        main()