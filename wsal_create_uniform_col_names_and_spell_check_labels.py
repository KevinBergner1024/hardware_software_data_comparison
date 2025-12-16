import os 
import pathlib
import pandas as pd 
import progressbar
import numpy as np
import argparse
import sys
import textwrap
import logging
from rich.logging import RichHandler        


NAME = "Create Uniform Column Names for All Sub Data Set Samples Script"
VERSION = "1.0.0"

DEFAULT_LOG_FILE = None
DEFAULT_DATE_LOG_FORMAT = "%Y-%m-%d %H:%M:%S"
HARDWARE_SIM_DEFAULT_LOG_FILE:pathlib.Path = pathlib.Path("")
SOFTWARE_SIM_DEFAULT_LOG_FILE:pathlib.Path = pathlib.Path("")
DEFAULT_LOG_FILE_LEVEL:int = logging.DEBUG
DEFAULT_LOG_FILE_FORMAT:str = '[%(asctime)s.%(msecs)6d][%(levelname)s] %(message)s'
DEFAULT_LOG_CONSOLE_LEVEL:int = logging.DEBUG
DEFAULT_LOG_CONSOLE_FORMAT:int = '[%(asctime)s.%(msecs)6d][%(levelname)s] %(message)s'
LOGGER:logging.Logger = None

LogLevel:dict = {
    "DEBUG":logging.DEBUG,
    "INFO":logging.INFO,
    "WARNING":logging.WARNING,
    "ERROR":logging.ERROR,
}

def create_log_file_handler(log_file:pathlib.Path=DEFAULT_LOG_FILE, log_file_level:int=DEFAULT_LOG_FILE_LEVEL,
                  log_file_format:str=DEFAULT_LOG_FILE_FORMAT) -> logging.FileHandler:
    f_handler = logging.FileHandler(log_file)
    f_handler.setLevel(log_file_level)
    f_format = logging.Formatter(log_file_format, datefmt=DEFAULT_DATE_LOG_FORMAT)
    f_handler.setFormatter(f_format)
    return f_handler

def create_logger(log_console_level:int=DEFAULT_LOG_CONSOLE_LEVEL, log_console_format:int=DEFAULT_LOG_CONSOLE_FORMAT,
                  log_file:pathlib.Path=DEFAULT_LOG_FILE, log_file_level:int=DEFAULT_LOG_FILE_LEVEL,
                  log_file_format:str=DEFAULT_LOG_FILE_FORMAT) -> logging.Logger:
    # Create a custom logger
    logger = logging.getLogger(__name__)
    logger.handlers = [RichHandler(level=log_console_level)]

    if log_file != None:
        f_handler = create_log_file_handler(log_file, log_file_level, log_file_format)
        logger.addHandler(f_handler)
    logger.setLevel(logging.DEBUG)

    return logger


def load_windows_security_auditing_logs_for_simuser_iteration(os_path_simuser_iteration: pathlib.Path, limited_rows: bool = False):
    
    if(limited_rows):
        wsal_df = pd.read_csv(pathlib.Path(os_path_simuser_iteration), dtype="string", nrows=1000, compression='gzip')
    else:
        wsal_df = pd.read_csv(pathlib.Path(os_path_simuser_iteration), dtype="string", compression='gzip')

    wsal_df["SYSTEM_TimeCreated"] = pd.to_datetime(wsal_df["SYSTEM_TimeCreated"]).dt.tz_localize(None)
    wsal_df.sort_values(by=["SYSTEM_TimeCreated"], inplace=True)
    wsal_df.sort_index(axis=1, inplace=True)
    wsal_df.reset_index(drop=True, inplace=True)

    return wsal_df

def get_uniform_column_values_and_event_ids_for_parsed_windows_security_audit_log_sub_data_sets(folder_path: pathlib.Path):
    """get uniform column names and event ids from all sub data sets in a folder path containing multiple sub data sets in gzip format

    Args:
        folder_path: (pathilib.Path): folder path containing multiple sub data sets in gzip format

    Returns:
        tuple:  list of event ids, list of uniform column names
    """

    column_names = []
    event_ids = []

    folder_content = os.listdir(folder_path)
    length = len([file_name for file_name in folder_content if ((".gz" in file_name))])
    counter = 0

    with progressbar.ProgressBar(max_value=length) as bar:
        bar.update(counter)
        for sub_path in folder_path.iterdir():
            if((sub_path.is_file()) & (".gz" in str(sub_path))):

                loaded_wsal_sub_data_set = load_windows_security_auditing_logs_for_simuser_iteration(os_path_simuser_iteration = sub_path, limited_rows= True)
                column_names_sub_data_set = list(loaded_wsal_sub_data_set.columns.values)

                # get column names
                for elem in column_names_sub_data_set:
                    if(elem not in column_names):
                        column_names.append(elem)

                counter = counter + 1
            bar.update(counter)
    
    return event_ids, column_names

def apply_uniform_column_names_to_sub_data_set_samples_and_save_data_in_gzip_format(folder_path_to_load_processed_sub_data_sets: pathlib.Path, uniform_column_names: list, folder_path_to_save_sub_data_sets_with_uniform_column_names: pathlib.Path):
    """apply uniform column names to all sub data set samples and save back the processed sub data sets in gzip format

    Args:
        folder_path_to_load_processed_sub_data_sets (pathilib.Path): folder path containing multiple sub data sets in gzip format
        uniform_column_names (list): list of uniform column names to apply to all sub data set samples
        folder_path_to_save_sub_data_sets_with_uniform_column_names (pathilib.Path): folder path to save back the processed sub data sets with uniform column names in gzip format

    Returns:
        -
    """

    folder_content = os.listdir(folder_path_to_load_processed_sub_data_sets)
    length = len([file_name for file_name in folder_content if ((".gz" in file_name))])
    counter = 0
    with progressbar.ProgressBar(max_value=length) as bar:
        bar.update(counter)
        for sub_path in folder_path_to_load_processed_sub_data_sets.iterdir():
            if((sub_path.is_file()) & (".gz" in str(sub_path))):
                loaded_wsal_sub_data_set = load_windows_security_auditing_logs_for_simuser_iteration(os_path_simuser_iteration = sub_path)

                column_names_sub_data_set = list(loaded_wsal_sub_data_set.columns.values)
                
                # check which uniform columns are missing in sub data set 
                missing_columns = list(set(uniform_column_names) - set(column_names_sub_data_set))

                # add missing columns with NaN values
                for missing_col in missing_columns:
                    loaded_wsal_sub_data_set[missing_col] = np.nan

                # reorder columns to match uniform column names
                loaded_wsal_sub_data_set.sort_index(axis=1, inplace=True)

                # get final column names after processing
                column_names_sub_data_set = list(loaded_wsal_sub_data_set.columns.values)

                # verify if columns match
                not_matching_columns = list(set(uniform_column_names) - set(column_names_sub_data_set)) + list(set(column_names_sub_data_set) - set(uniform_column_names))

                LOGGER.info("After processing %s , uniform column values not in sub data set remaining:  %s"%(sub_path.name, str(not_matching_columns)))

                LOGGER.info("%s included event ids:  %s"%(sub_path.name, str(loaded_wsal_sub_data_set["SYSTEM_EventID"].unique().tolist())))

                LOGGER.info("%s value count included event ids (%s unique event ids included):  %s"%(sub_path.name,str(len(loaded_wsal_sub_data_set["SYSTEM_EventID"].unique().tolist())), str(loaded_wsal_sub_data_set["SYSTEM_EventID"].value_counts().to_string().replace("\n", "; "))))

                # add spelling check for column names here if needed
                loaded_wsal_sub_data_set['Labels'] = loaded_wsal_sub_data_set['Labels'].str.replace("recieve", "receive")

                LOGGER.info("%s included behavior 'Labels' (total %s labels):  %s"%(sub_path.name, str(len(loaded_wsal_sub_data_set["Labels"].unique().tolist())), str(loaded_wsal_sub_data_set["Labels"].unique().tolist())))

                LOGGER.info("%s DataFrame shape:  %s"%(sub_path.name, str(loaded_wsal_sub_data_set.shape)))
                # save back the processed sub data set
                loaded_wsal_sub_data_set.to_csv(pathlib.Path.joinpath(folder_path_to_save_sub_data_sets_with_uniform_column_names, sub_path.name), index=False, compression='gzip')

                counter = counter + 1
            bar.update(counter)


def main(hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns: str,
        hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns: str,
        software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns: str,
        software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns: str,
        simulation_run_data_to_process: str = "hardware_simulation"):

    try:
        LOGGER.info("Start %s v%s"%(NAME, VERSION))

        hardware_sim_event_ids, hardware_sim_column_names = get_uniform_column_values_and_event_ids_for_parsed_windows_security_audit_log_sub_data_sets(folder_path = pathlib.Path(hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns))
        software_sim_event_ids, software_sim_column_names = get_uniform_column_values_and_event_ids_for_parsed_windows_security_audit_log_sub_data_sets(folder_path = pathlib.Path(software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns))
        
        combined_column_names = list(set(hardware_sim_column_names + software_sim_column_names))

        if(simulation_run_data_to_process == "hardware_simulation"):
            LOGGER.info("Hardware simulation extracted uniformn column values from all sub data sets (total %s column values):  %s"%(str(len(hardware_sim_column_names)), str(hardware_sim_column_names)))
            apply_uniform_column_names_to_sub_data_set_samples_and_save_data_in_gzip_format(folder_path_to_load_processed_sub_data_sets = pathlib.Path(hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns), 
                                                                                            uniform_column_names = combined_column_names,
                                                                                            folder_path_to_save_sub_data_sets_with_uniform_column_names = pathlib.Path(hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns))
        
        elif(simulation_run_data_to_process == "software_simulation"):
            LOGGER.info("Software simulation extracted uniformn column values from all sub data sets (total %s column values):  %s"%(str(len(software_sim_column_names)), str(software_sim_column_names)))
            apply_uniform_column_names_to_sub_data_set_samples_and_save_data_in_gzip_format(folder_path_to_load_processed_sub_data_sets = pathlib.Path(software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns), 
                                                                                            uniform_column_names = combined_column_names,
                                                                                            folder_path_to_save_sub_data_sets_with_uniform_column_names = pathlib.Path(software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns))
        LOGGER.info("Completed %s v%s"%(NAME, VERSION))

    except Exception as e:

        LOGGER.exception("Exception: %s"%(e))

    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
    ---------------------------------------------------------------
    Name: %s
    Version: %s
    ---------------------------------------------------------------
    Usage: python wsal_create_uniform_col_names_and_spell_check_labels.py /home/hardware_sim_data_non_uniform_cols/  /home/hardware_sim_data_uniform_cols/ /home/software_sim_data_non_uniform_cols/  /home/software_sim_data_uniform_cols/ hardware_simulation
    ''')%(NAME, VERSION)))
    
    parser.add_argument('hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns', type = str, help = "system path which includes compressed (gzip) Windows 10 security audit log files for hardware simulation (type:str) (e.g., /home/hardware_sim_data_non_uniform_cols/)")
    parser.add_argument('hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns', type = str, help = "system path, to store Windows 10 security audit log files with uniform columns for hardware simulation (type:str) (e.g., /home/hardware_sim_data_uniform_cols/)")

    parser.add_argument('software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns', type = str, help = "system path which includes compressed (gzip) Windows 10 security audit log files for software simulation (type:str) (e.g., /home/software_sim_data_non_uniform_cols/)")
    parser.add_argument('software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns', type = str, help = "system path, to store Windows 10 security audit log files with uniform columns for software simulation (type:str) (e.g., /home/software_sim_data_uniform_cols/)")

    parser.add_argument('simulation_run_data_to_process', type = str, help = "'hardware_simulation' or 'software_simulation' to data folder to create uniform column values for", default="hardware_simulation")
    
    args = parser.parse_args()
    
    hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns_cmd = args.hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns
    hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns_cmd = args.hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns

    software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns_cmd = args.software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns
    software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns_cmd = args.software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns
    simulation_run_data_to_process_cmd = args.simulation_run_data_to_process
    
    if(simulation_run_data_to_process_cmd == "hardware_simulation"):
        DEFAULT_LOG_FILE = HARDWARE_SIM_DEFAULT_LOG_FILE
    elif(simulation_run_data_to_process_cmd == "software_simulation"):
        DEFAULT_LOG_FILE = SOFTWARE_SIM_DEFAULT_LOG_FILE

    LOGGER = create_logger(log_file=DEFAULT_LOG_FILE, log_console_level=LogLevel["INFO"])
    LOGGER.debug("Start from console: %s"%(" ".join(list(sys.argv))))

    return_code = main(hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns = hardware_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns_cmd,
                       hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns = hardware_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns_cmd,
                       software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns = software_sim_os_path_folder_to_load_all_processed_sub_data_sets_with_non_uniform_columns_cmd,
                       software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns = software_sim_os_path_folder_to_save_all_processed_sub_data_sets_with_uniform_columns_cmd,
                       simulation_run_data_to_process = simulation_run_data_to_process_cmd)
    
    quit(return_code)
