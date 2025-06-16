import configparser
import pathlib
import datetime
import argparse
import textwrap
import os

NAME = "Sim23 Log Parser Script"
VERSION = "1.3"
CMD_MODE_ENABLED = False

def load_config_asset(config_section: str, config_key: str, config_system_path: pathlib.Path = pathlib.Path(__file__).with_name('config.ini')):
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

def load_sim23_log_data_without_using_predefined_labels(sim23_log_system_path: str = load_config_asset("LOGPATHS", "sim23_log_system_path"),
                                                        sim23_log_start_behavior_tag: str = "Execute Behaviour command for", datetime_format: str = '%Y-%m-%d_%H-%M-%S.%f'):
    """load sim23 log data for specific recording iteration without predefined labels

    Args:
        sim23_log_system_path (str): path to sim23 log file on system. Defaults to load_config_asset("LOGPATHS", "sim23_log_system_path").
        sim23_log_start_behavior_tag (str): text which indicates that sim23 row contains important behavior. Defaults to "Execute Behaviour command for".
        datetime_format (str): datetime format for parsed sim23 log time stamps. Defaults to '%Y-%m-%d_%H-%M-%S.%f'.

    Returns:
        list: list with tuples that have following structure: (start_time_behavior, end_time_behavior, behavior_label)
    """
    if(os.name == "nt"):
        sim23_log_system_path_parsed = pathlib.WindowsPath(sim23_log_system_path)
    else:
        sim23_log_system_path_parsed = pathlib.Path(sim23_log_system_path)
 
    data_sim23_logs = sim23_log_system_path_parsed.read_text()
    data_sim23_logs_splitted = data_sim23_logs.split("\n")
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
    return parsed_sim23_log_behavior_list

def main():
    
    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
        This script is called by main experiment scripts (starting with 'wsal_') on highest hierachy of this repository structure.
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