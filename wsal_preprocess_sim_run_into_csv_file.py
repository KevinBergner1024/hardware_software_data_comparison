import argparse
import textwrap
import pandas as pd
import pathlib
import configparser
import os
import datetime

from process_wal import process_wal
from parsing_sim23_logs import parse_sim23_logs

NAME = "WSAL PREPROCESSING DATA INTO COMPRESSED CSVs FOR MACHINE LEARNING SCRIPT"
VERSION = "1.3"
CMD_MODE_ENABLED = True

def load_config_asset(config_section:str, config_key:str, config_system_path:pathlib.Path=pathlib.Path(__file__).with_name('config.ini')):
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

def load_complete_simulation_rum_for_specific_simuser(system_path_simulation_run:pathlib.Path,
                            archived_wal_substring:str="Archive-Security",
                            system_path_next_simulation_run:pathlib.Path=None,
                            sim_user_of_interest:str="SimUser001",
                            sim23_logs_file_name:str="sim23.log",
                            timezone_of_simulation_run:str="CET",
                            system_Path_to_store_iteration:pathlib.Path=None
                            ):
    """load complete simulation run into compressed (gzip) csv file for specific simulation simuser (001, 002, 003, 004)

    Args:
        system_path_simulation_run (pathlib.Path): system path to load the main simulation run XML files from
        archived_wal_substring (str, optional): substring included in every Windows security audit log file. Defaults to "Archive-Security".
        system_path_next_simulation_run (pathlib.Path, optional): edge case -> load data for current simulation run which is extracted in the next simulatio run. Defaults to None.
        sim_user_of_interest (str, optional): simulation user of interest. Defaults to "SimUser001".
        sim23_logs_file_name (str, optional): name of sim 23 log file to parse data labels. Defaults to "sim23.log".
        timezone_of_simulation_run (str, optional): timezone of simulation run (next and current simulation run have always the same timezone). Defaults to "CET".
        system_Path_to_store_iteration (pathlib.Path): system path to store converted simulation iteration in compressed format. Defaults to "None".

    Returns:
        -
    """
    # get complete structure of folder which contains sim23 logs and convertet (in XML format) wal archived files -> the whole folder is the run folder
    # return structure of os.walk: (current system  path in folder, [included sub folder], [included files])
    complete_system_path_structure = [entry for entry in os.walk(system_path_simulation_run)]
    # correct spelling: converted, but used existing folder structure name from nas
    archived_wals_system_paths = sorted([entry for entry in complete_system_path_structure if (any(archived_wal_substring in file for file in entry[2])) & (sim_user_of_interest in entry[0]) & ("convertet_wal" in entry[0])])
    sim23_log_system_paths = sorted([entry[0] for entry in complete_system_path_structure if (sim23_logs_file_name in entry[2]) & (sim_user_of_interest in entry[0]) & ("Postrun" not in entry[0]) & ("Prerun" not in entry[0]) & ("Invalid" not in entry[0])])
    # for iteration in simuser specific run
    for idx, entry in enumerate(archived_wals_system_paths):
        wal_logs = process_wal.load_windows_audit_logs_from_system_folder(pathlib.Path(entry[0]), remove_linux_wal_converter_artefacts=False, timezone_of_simulation_run= timezone_of_simulation_run)
        sim23_logs = parse_sim23_logs.load_sim23_log_data_without_using_predefined_labels(sim23_log_system_path=pathlib.Path.joinpath(pathlib.Path(sim23_log_system_paths[idx]), sim23_logs_file_name))

        # last iteration in run for specific user -> access archived xml file from next run
        if(idx == (len(archived_wals_system_paths)-1)):
            # get complete structure of next run for the same sim user  
            next_run_complete_system_path_structure = [entry for entry in os.walk(system_path_next_simulation_run)]
            next_run_archived_wals_system_paths = sorted([entry for entry in next_run_complete_system_path_structure if (any(archived_wal_substring in file for file in entry[2])) & (sim_user_of_interest in entry[0]) & ("convertet_wal" in entry[0])])
            # get the first archived security file based on file name export timestamps
            file_to_get = None
            for file in sorted(next_run_archived_wals_system_paths[0][2]):
                if(archived_wal_substring in file):
                    file_to_get = file
                    # stop if first archived security file is found
                    break
            if(file_to_get != None):
                additional_wal_logs = process_wal.load_windows_audit_logs_from_system_file(pathlib.Path.joinpath(pathlib.Path(next_run_archived_wals_system_paths[0][0]), file_to_get), remove_linux_wal_converter_artefacts=False, timezone_of_simulation_run=timezone_of_simulation_run)
            if(not additional_wal_logs.empty):
                frames = [wal_logs, additional_wal_logs]
                wal_logs = pd.concat(frames, copy=False, ignore_index=True, axis=0)
                wal_logs = wal_logs.sort_values(by="SYSTEM_TimeCreated", ignore_index=True) 
                additional_wal_logs = pd.DataFrame()
                # DONE improvement sugggestion: set additional_wal_logs = pd.DataFrame() -> empty dataframe
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
                additional_wal_logs = process_wal.load_windows_audit_logs_from_system_file(pathlib.Path.joinpath(pathlib.Path(archived_wals_system_paths[idx+1][0]), file_to_get), remove_linux_wal_converter_artefacts=False, timezone_of_simulation_run=timezone_of_simulation_run)
            if(not additional_wal_logs.empty):
                frames = [wal_logs, additional_wal_logs]
                wal_logs = pd.concat(frames, ignore_index=True, copy=False, axis=0)
                wal_logs = wal_logs.sort_values(by="SYSTEM_TimeCreated", ignore_index=True)
                additional_wal_logs = pd.DataFrame()
                # DONE improvement sugggestion: set additional_wal_logs = pd.DataFrame() -> empty dataframe


        # REMOVED wal_logs = wal_logs[wal_logs['EVENTDATA_SubjectUserName'] == sim_user_of_interest]
        
        # START cut iteration by iteration timestamps
        current_iteration_time_start_end_timestamps = pathlib.Path.joinpath(pathlib.Path(sim23_log_system_paths[idx]), "iteration.time").read_text().split("#")
        parsed_current_iteration_time_start_end_timestamps = (datetime.datetime.strptime(current_iteration_time_start_end_timestamps[0], '%Y-%m-%d %H:%M:%S'),
                                                                                     datetime.datetime.strptime(current_iteration_time_start_end_timestamps[1], '%Y-%m-%d %H:%M:%S'))
        
        wal_logs = wal_logs.loc[(wal_logs["SYSTEM_TimeCreated"] >= parsed_current_iteration_time_start_end_timestamps[0]) & (wal_logs["SYSTEM_TimeCreated"] <= parsed_current_iteration_time_start_end_timestamps[1])]
        # END cut iteration by iteration timestamps

        wal_logs = wal_logs.sort_values(by="SYSTEM_TimeCreated", ignore_index=True)
        # label windows security audit logs
        wal_logs = process_wal.attach_sim_23_logs_labels_col_windows_audit_logs(wal_logs, sim23_logs=sim23_logs)
        # renaming structure failed for pc124 -> "_home_kevin_mnt_nas_" instead of "_home_kevin_mnt_nas_stack_" -> fixed the naming issue manually afterwards
        path_to_store_iteration = pathlib.Path.joinpath(system_Path_to_store_iteration, str(system_path_simulation_run).replace("/", "_").replace(" ", "_").replace("_home_kevin_mnt_nas_", "") + "_iteration_" + str(idx) + "_" + sim_user_of_interest + "_converted_and_labeled_data.gz")
        wal_logs.to_csv(path_to_store_iteration, index=False, compression="gzip")

def main(path_run_to_evaluate:str=None, path_to_next_run:str=None, sim_user_of_interest:str=None, timezone:str="CET", system_path_to_save_converted_file:str=None):  
    load_complete_simulation_rum_for_specific_simuser(system_path_simulation_run=pathlib.Path(path_run_to_evaluate), system_path_next_simulation_run=pathlib.Path(path_to_next_run), sim_user_of_interest=sim_user_of_interest, timezone_of_simulation_run=timezone, system_Path_to_store_iteration=pathlib.Path(system_path_to_save_converted_file))
    return 0    

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog=NAME,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent(('''
        This script converts a complete simulation run for a specific user
        from XML to CSV file format. The stored CSV file is compressed by
        default to reduce the storage usage of the host system. Each run 
        
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage:
        ''')%(NAME, VERSION)))

        parser.add_argument('system_path_simulation_run_folder', type=str, help="simulation run system folder to convert included XML files into CSV file (type:str) (e.g., /home/kevin/mnt/nas/simdata/hardware_sim23/Hardware Sim 23 Run 9 [41-45])")
        parser.add_argument('system_path_next_simulation_run_folder', type=str, help="next simulation system folder which contains simulation run after the focused run in the previous parameter system_path_simulation_run_folder. The first timeline-sorted WSAL XML file will be convertet to a CSV file as well (type:str) (e.g., /home/kevin/mnt/nas/simdata/hardware_sim23/[INVALID] Hardware Sim 23 Run 10 [46-50])")
        parser.add_argument('sim_user', type=str, help="simuser of interest to convert simulation run for. In detail WSAL XML into CSV file (type:str) (e.g., SimUser001)")
        parser.add_argument('timezone_of_simulation_run', type=str, help="timezone in which the simulation run of interest is recorded (type:str) (CET or CEST)")
        parser.add_argument('path_to_save_convertet_csv_files_of_simulation_run_for_specific_simuser', type=str, help="system path to store the compressed CSV file (type:str) (e.g., /home/user/data/storage_data_mining")
        args = parser.parse_args()
        system_path_simulation_run_folder_cmd = args.system_path_simulation_run_folder
        system_path_next_simulation_run_cmd = args.system_path_next_simulation_run_folder
        sim_user_cmd = args.sim_user
        timezone_of_simulation_run_cmd = args.timezone_of_simulation_run
        path_to_save_convertet_csv_files_of_simulation_run_for_specific_simuser_cmd = args.path_to_save_convertet_csv_files_of_simulation_run_for_specific_simuser
        return_code = main(system_path_simulation_run_folder_cmd, system_path_next_simulation_run_cmd, sim_user_cmd, timezone_of_simulation_run_cmd, path_to_save_convertet_csv_files_of_simulation_run_for_specific_simuser_cmd)
        quit(return_code)
    else:
        main()