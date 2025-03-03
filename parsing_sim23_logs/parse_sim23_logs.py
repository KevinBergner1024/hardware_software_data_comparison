import configparser
import pathlib
import datetime
import argparse
import textwrap
import os

NAME = "Sim23 Log Parser Script"
VERSION = "1.3"
CMD_MODE_ENABLED = False

def load_config_asset(config_section:str, config_key:str, config_system_path:pathlib.Path=pathlib.Path(__file__).with_name('config.ini')):
    """load configuration content from config file

    Args:
        config_section (str): section in config file
        config_key (str): key value of config section
        config_system_path (pathlib.Path, optional): system path to config file

    Returns:
        str: configuration value queried for
    """
    try:
        config_object = configparser.ConfigParser()
        config_object.read(config_system_path)
        config_section = config_object[config_section]
        config_key_value = config_section[config_key]
    except:
        print("METHOD: load_config_asset throws exception!")

    return config_key_value

def load_sim23_log_labels(host_data_labels_file_system_path:pathlib.Path=pathlib.Path(__file__).with_name('host_data_labels.txt'), substring_to_remove:str="\n"):
    """load sim23 log labels from pre-defined label collection, for those lables will be search in the sim23 logs later

    Args:
        host_data_labels_file_system_path (pathlib.Path): path to file which stores the pre-defined behavior labels for single recording iteration
        substring_to_remove (str, optional): substring to remove from labels while reading them from the file. Defaults to "\n".

    Returns:
        list: list of strings which contains the labels
    """
    try:
        file = open(host_data_labels_file_system_path)
        file_content = file.readlines()
        labels = []
        if(substring_to_remove != None):
            for label in file_content:
                label = label.replace(substring_to_remove, "")
                labels.append(label)
        else:
            for label in file_content:
                labels.append(label)
    except:
        print("METHOD: read_sim23_log_labels throws exception!")

    return labels

def check_sim23_log_entry_matches_host_data_labels(sim23_log_entry:str):
    """filter method to decide if row includes important simulation behavior

    Args:
        sim23_log_entry (str): row of sim23 log file

    Returns:
        bool: true if important behavior is included, false if not
    """
    labels = load_sim23_log_labels()
    for label in labels:
        if(label in sim23_log_entry):
            return True

    return False

def check_sim23_log_entry_which_label_included_in_row_entry(row_entry_sim23_logs:str):
    """check which simulation behaivor is included in sim23 row

    Args:
        row_entry_sim23_logs (str): sim23 log row

    Raises:
        Exception: no pre-defined label is included in specific row

    Returns:
        str: label with included behavior or throw exception that no label included for specific row
    """
    try:
        labels = load_sim23_log_labels()
        for idx, label in enumerate(labels):
            # bug is included here, should be fixed now
            row_entry_sim23_log_label = row_entry_sim23_logs.split("'")
            if(label == row_entry_sim23_log_label[1]):
                return label
        raise Exception("METHOD: check_sim23_log_entry_which_label_included_in_row_entry throws execption")
    except Exception:
        print(Exception)

def load_sim23_log_data(sim23_log_system_path:str=load_config_asset("LOGPATHS", "sim23_log_system_path"), sim23_log_start_behavior_tag:str="Execute Behaviour command for", datetime_format:str='%Y-%m-%d_%H-%M-%S.%f'):
    """load sim23 log data for specific recording iteration

    Args:
        sim23_log_system_path (str, optional): path to sim23 log file on system. Defaults to load_config_asset("LOGPATHS", "sim23_log_system_path").
        sim23_log_start_behavior_tag (str, optional): text which indicates that sim23 row contains important behavior. Defaults to "Execute Behaviour command for".
        datetime_format (str, optional): datetime format for parsed sim23 log time stamps. Defaults to '%Y-%m-%d_%H-%M-%S.%f'.

    Returns:
        list: list with tuples that have following structure: (start_time_behavior, end_time_behavior, behavior_label)
    """
    if(os.name == "nt"):
        sim23_log_system_path_parsed = pathlib.WindowsPath(sim23_log_system_path)
    else:
        sim23_log_system_path_parsed = pathlib.Path(sim23_log_system_path)
    
    sim23_log_file = open(sim23_log_system_path_parsed)
    sim23_log_file_content = sim23_log_file.readlines()        

    # check element-wise if behavior labels are included in sim23 log entries (row-wise)
    user_behavior_sim23_log_file_entries = list(filter(check_sim23_log_entry_matches_host_data_labels, sim23_log_file_content))
    # load index of entries which describe start of behavior in sim23 logs
    index_start_behavior_command = [row_index for row_index in range(len(user_behavior_sim23_log_file_entries)) if (sim23_log_start_behavior_tag in user_behavior_sim23_log_file_entries[row_index])]

    parsed_sim23_log_behavior_list = []
    for index_value in index_start_behavior_command:
        # timestamp format varies for different behavior entries regarding last mili second information
        # this implementation cuts variable timestamp length based on log entry format
        start_behavior_row = user_behavior_sim23_log_file_entries[index_value].split('[INFO]')[0][1:-1]
        end_behavior_row = user_behavior_sim23_log_file_entries[index_value+1].split('[INFO]')[0][1:-1]

        behavior_tuple = (datetime.datetime.strptime(start_behavior_row, datetime_format), datetime.datetime.strptime(end_behavior_row, datetime_format), check_sim23_log_entry_which_label_included_in_row_entry(user_behavior_sim23_log_file_entries[index_value]))
        parsed_sim23_log_behavior_list.append(behavior_tuple) 

    # length of label pattern must be 82 entries long
    return parsed_sim23_log_behavior_list

def load_sim23_log_data_without_using_predefined_labels(sim23_log_system_path:str=load_config_asset("LOGPATHS", "sim23_log_system_path"), sim23_log_start_behavior_tag:str="Execute Behaviour command for", datetime_format:str='%Y-%m-%d_%H-%M-%S.%f'):
    """load sim23 log data for specific recording iteration without predefined labels

    Args:
        sim23_log_system_path (str, optional): path to sim23 log file on system. Defaults to load_config_asset("LOGPATHS", "sim23_log_system_path").
        sim23_log_start_behavior_tag (str, optional): text which indicates that sim23 row contains important behavior. Defaults to "Execute Behaviour command for".
        datetime_format (str, optional): datetime format for parsed sim23 log time stamps. Defaults to '%Y-%m-%d_%H-%M-%S.%f'.

    Returns:
        list: list with tuples that have following structure: (start_time_behavior, end_time_behavior, behavior_label)
    """
    if(os.name == "nt"):
        sim23_log_system_path_parsed = pathlib.WindowsPath(sim23_log_system_path)
    else:
        sim23_log_system_path_parsed = pathlib.Path(sim23_log_system_path)
 
    data_sim23_logs = sim23_log_system_path_parsed.read_text()
    data_sim23_logs_splitted = data_sim23_logs.split("\n")
    # select logged behavior in sim23 logs
    parsed_sim23_log_behavior_list = []
    for idx, element in enumerate(data_sim23_logs_splitted):
        if(sim23_log_start_behavior_tag in element):

            behavior_label = element.split("'")[1]
            # timestamp format varies for different behavior entries regarding last mili second information
            # this implementation cuts variable timestamp length based on log entry format
            behvavior_start = element.split('[INFO]')[0][1:-1]
            behavior_end = data_sim23_logs_splitted[idx +1].split('[INFO]')[0][1:-1]
        
            single_behavior_info = (datetime.datetime.strptime(behvavior_start, datetime_format), datetime.datetime.strptime(behavior_end, datetime_format), behavior_label)
            parsed_sim23_log_behavior_list.append(single_behavior_info)
    # length of label pattern must be 82 entries long
    return parsed_sim23_log_behavior_list

def main():
    test = load_sim23_log_data(r"C:\Users\kev8693m\Downloads\sim23(2).log")
    test2 = load_sim23_log_data_without_using_predefined_labels(r"C:\Users\kev8693m\Downloads\sim23(2).log")

    print(test==test2)
    
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