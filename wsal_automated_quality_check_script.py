import argparse
import textwrap
import pandas as pd
import pathlib
import datetime
import configparser
import os
import logging

from process_wal import process_wal
from parsing_sim23_logs import parse_sim23_logs
from quality_evaluation import wal_quality_evaluation

NAME = "WSAL AUTOMATED QUALITY CHECK SCRIPT"
VERSION = "1.8"
CMD_MODE_ENABLED = True

def load_config_asset(config_section: str, config_key: str, config_system_path: pathlib.Path = pathlib.Path(__file__).with_name('config.ini')):
    """load configuration content from config file

    Args:
        config_section (str): section in config file
        config_key (str): key value of config section
        config_system_path (pathlib.Path, optional): system path to config file. Defaults to CONFIG_INI_SYSTEM_PATH.

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

def automated_quality_check_windows_security_audit_logs(simulation_run_system_folder_path: pathlib.Path, folder_path_to_log_quality_evaluation_results: pathlib.Path = None, archived_wal_substring: str = "Archive-Security",
                            next_simulation_run_system_folder_path: pathlib.Path = None, sim23_logs_file_name: str = "sim23.log", sim_user_of_interest: str = None, timezone_of_simulation_run: str = "CET"):
    """automated quality check for specific simulation run (hardware or software data) for specified Windows 10 user client

    Args:
        simulation_run_system_folder_path (pathlib.Path): simulation run folder containing all the sim data (e.g., /home/path/to/data/Hardware Sim 23 Run 9 [41-45])
        folder_path_to_log_quality_evaluation_results (pathlib.Path): folder path to save the created Windows 10 security audit logs quality check report.
        archived_wal_substring (str): substring always contained in converted Windows 10 security audit logs xml file names.
        next_simulation_run_system_folder_path (pathlib.Path): next simulation run which follows simulation_run_system_folder_path.
        sim23_logs_file_name (str): name of sim 23 log file.
        sim_user_of_interest (str): simulation user of interest.
        timezone_of_simulation_run (str): timezone of simulation run (next and current simulation run have always the same timezone). Defaults to "CET".

    Returns: 
        -, creates log file with evaluation results included.
    """
    complete_system_path_structure = [entry for entry in os.walk(simulation_run_system_folder_path)] # return structure of os.walk: (current system  path in folder, [included sub folder], [included files])
    sim23_log_system_paths = sorted([entry[0] for entry in complete_system_path_structure if (sim23_logs_file_name in entry[2]) & (sim_user_of_interest in entry[0]) & ("Postrun" not in entry[0]) & ("Prerun" not in entry[0]) & ("Invalid" not in entry[0])])
    archived_wals_system_paths = sorted([entry for entry in complete_system_path_structure if (any(archived_wal_substring in file for file in entry[2])) & (sim_user_of_interest in entry[0]) & ("convertet_wal" in entry[0])])
    info_to_log = None
    file_path_name_wal_logging = None

    try:
        if(sim23_log_system_paths):
            splitted_first_itreation_of_specified_user_path = sim23_log_system_paths[0].split('/')
            info_to_log = splitted_first_itreation_of_specified_user_path[-4] + "_" + splitted_first_itreation_of_specified_user_path[-3] + "_" + splitted_first_itreation_of_specified_user_path[-2]
            # if code is running on windows os
            if os.name == 'nt':
                info_to_log = "test_of_script_windows_os"
            file_path_name_wal_logging = pathlib.Path.joinpath(folder_path_to_log_quality_evaluation_results, (info_to_log + ".log"))
        else:
            raise ValueError("system path for simuser sim23 logs does not exist")
        
        if(os.path.isdir(folder_path_to_log_quality_evaluation_results)):
            # clears content of existing file first
            open(file_path_name_wal_logging, 'w').close()
            logging.basicConfig(filename=file_path_name_wal_logging, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S", level=logging.DEBUG)
            logging.info('|%s|%s', NAME, VERSION)
            logging.info('|%s|%s', info_to_log, 'complete automated windows security audit logs quality evaluation started')
        else:
            raise ValueError("logging path for quality evaluation does not exist")
        
        if(sim_user_of_interest == None):
            raise ValueError("simulation user must be defined")
        
    except ValueError as err:
        print(err, "error while loading data")

    # enumerate through simulation iterations of interest by starting with earliest to latest iteration
    for idx, sim23_log in enumerate(sim23_log_system_paths):
        current_sim23_log_entries = parse_sim23_logs.load_sim23_log_data_without_using_predefined_labels(pathlib.Path.joinpath(pathlib.Path(sim23_log), sim23_logs_file_name))        
        current_iteration_time_start_end_timestamps = pathlib.Path.joinpath(pathlib.Path(sim23_log), "iteration.time").read_text().split("#") # index of list: 0 == start, 1 == end
        parsed_current_iteration_time_start_end_timestamps = (datetime.datetime.strptime(current_iteration_time_start_end_timestamps[0], '%Y-%m-%d %H:%M:%S'), datetime.datetime.strptime(current_iteration_time_start_end_timestamps[1], '%Y-%m-%d %H:%M:%S'))
        current_sim23_logs_based_on_iteration_time = []

        for entry in current_sim23_log_entries:
            # first index of sim 23 log entry start time behavior | second index of sim 23 log entry end time behavior
            if((entry[0] >= parsed_current_iteration_time_start_end_timestamps[0]) & (entry[1] <= parsed_current_iteration_time_start_end_timestamps[1])):
                current_sim23_logs_based_on_iteration_time.append(entry)

        wal_logs = process_wal.load_windows_audit_logs_from_system_folder(pathlib.Path(archived_wals_system_paths[idx][0]), remove_linux_wal_converter_artefacts = False, timezone_of_simulation_run = timezone_of_simulation_run, quality_check_fast_mode_enabled = True)
        
        # last iteration in run for specific user -> access archived xml file from next run
        if(idx == (len(sim23_log_system_paths)-1)):
            # get complete structure of next run for the same sim user  
            next_run_complete_system_path_structure = [entry for entry in os.walk(next_simulation_run_system_folder_path)]
            next_run_archived_wals_system_paths = sorted([entry for entry in next_run_complete_system_path_structure if (any(archived_wal_substring in file for file in entry[2])) & (sim_user_of_interest in entry[0]) & ("convertet_wal" in entry[0])])
            # get the first archived security file based on file name export timestamps
            file_to_get = None
            for file in sorted(next_run_archived_wals_system_paths[0][2]):
                if(archived_wal_substring in file):
                    file_to_get = file
                    # stop if first archived security file is found
                    break
            if(file_to_get != None):
                additional_wal_logs = process_wal.load_windows_audit_logs_from_system_file(pathlib.Path.joinpath(pathlib.Path(next_run_archived_wals_system_paths[0][0]), file_to_get), remove_linux_wal_converter_artefacts = False, timezone_of_simulation_run = timezone_of_simulation_run, quality_check_fast_mode_enabled = True)
            if(not additional_wal_logs.empty):
                wal_logs = pd.concat([wal_logs, additional_wal_logs], axis=0).sort_values(by = "SYSTEM_TimeCreated", ignore_index = True)
            else:
                logging.warning('|%s', 'last iteration of the run the next run file could not be found')
        
        # isn't last iteration in run for specific user -> access archived xml file from next iteration in same run
        else:
            # get the first archived security file based on file name export timestamps (for specific user in the next iteration of the simulation run)
            file_to_get = None
            for file in sorted(archived_wals_system_paths[idx+1][2]):
                if(archived_wal_substring in file):
                    file_to_get = file
                    # stop if first archived security file is found
                    break
            if(file_to_get != None):
                additional_wal_logs = process_wal.load_windows_audit_logs_from_system_file(pathlib.Path.joinpath(pathlib.Path(archived_wals_system_paths[idx+1][0]), file_to_get), remove_linux_wal_converter_artefacts = False, timezone_of_simulation_run = timezone_of_simulation_run, quality_check_fast_mode_enabled = True)
            if(not additional_wal_logs.empty):
                wal_logs = pd.concat([wal_logs, additional_wal_logs], axis = 0).sort_values(by = "SYSTEM_TimeCreated", ignore_index = True)
            else:
                logging.warning('|%s|%s|%s', 'iteration index', str(idx), 'next iteration of the current run could not be found')
       
        wal_logs = wal_logs[wal_logs['EVENTDATA_SubjectUserName'] == sim_user_of_interest]
        
        count_done_checks = wal_quality_evaluation.wal_general_quality_check_handler_sim23_log_based(sim23_logs = current_sim23_logs_based_on_iteration_time, audit_data = wal_logs, logging_path = file_path_name_wal_logging, sim_user_of_interest = sim_user_of_interest, timezone = timezone_of_simulation_run)
        logging.info('|%s|%s', info_to_log, 'automated windows security audit logs quality evaluation for iteration done')
    
        # check if all quality checks are done as expected based on count of checks done
        if(count_done_checks == 54):
            logging.info('|%s|%s', info_to_log, 'number of done quality checks is equal 54 as expected')
        else:
            logging.warning('|%s|%s %s', info_to_log, 'number of done quality checks is unequal 54', str(count_done_checks))

    logging.info('|%s|%s', info_to_log, 'complete automated windows security audit logs quality evaluation done')

def main(path_run_to_evaluate:str, path_to_next_run: str, sim_user_of_interest: str, folder_path_quality_evaluation: str, timezone: str):  

    automated_quality_check_windows_security_audit_logs(simulation_run_system_folder_path = pathlib.Path(path_run_to_evaluate), next_simulation_run_system_folder_path = pathlib.Path(path_to_next_run), 
                                                        sim_user_of_interest = sim_user_of_interest, folder_path_to_log_quality_evaluation_results = pathlib.Path(folder_path_quality_evaluation), timezone_of_simulation_run = timezone)
    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
        This script evaluates a complete hardware or software simulation run (a single run contains 5 iterations) for a specific Windows 10 client user. 
        Additionally, the results of the Windows 10 security audit log quality evaluations will be logged as well.
        This script requires the XML-parsed Windows 10 security audit logs. Please contact the corresponding authors for this data.
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage: python wsal_automated_quality_check_script.py /home/path/to/data/hardware_sim23/"Hardware Sim 23 Run 9 [41-45]" /home/path/to/data/hardware_sim23/"Hardware Sim 23 Run 10 [46-50]" SimUser001 /home/path/to/computation/results/quality_evaluation_logs
        ''')%(NAME, VERSION)))

        parser.add_argument('path_run_to_evaluate', type = str, help = "system path to simulation run to evaluate (type:str) (e.g., /home/path/to/data/Hardware Sim 23 Run 9 [41-45])")
        parser.add_argument('path_to_next_run', type = str, help = "system path to simulation run directly recorded after the run evaluated with this script (type:str) (e.g., /home/path/to/data/Hardware Sim 23 Run 10 [46-50])")
        parser.add_argument('sim_user', type = str, help = "simulation user of interest (type:str) (e.g., SimUser001)")
        parser.add_argument('folder_path_quality_evaluation', type = str, help = "folder path to create quality check reports in (type:str) (e.g., /home/path/to/computation/results/quality_evaluation_logs/)")
        parser.add_argument('timezone_of_simulation_run', type = str, help = "timezone in which the simulation run of interest was recorded (type:str) (CET or CEST)")
        args = parser.parse_args()
        path_run_to_evaluate_cmd = args.path_run_to_evaluate
        path_to_next_run_cmd = args.path_to_next_run
        sim_user_cmd = args.sim_user
        folder_path_quality_evaluation_cmd = args.folder_path_quality_evaluation
        timezone_of_simulation_run_cmd = args.timezone_of_simulation_run
        return_code = main(path_run_to_evaluate_cmd, path_to_next_run_cmd, sim_user_cmd, folder_path_quality_evaluation_cmd, timezone_of_simulation_run_cmd)
        quit(return_code)
    else:
        main()