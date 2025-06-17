import argparse
import textwrap
import pandas as pd
import pathlib
import os
import logging
import resource

from machine_learning import classification_ml_wsal
from machine_learning import encodings_wsal
from process_wal import process_wal
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split

NAME = "WSAL MAIN MACHINE LEARNING SCRIPT"
VERSION = "1.11"
CMD_MODE_ENABLED = True

# NOTICE: software run has one more file _rerun_09_ which is excluded at this point to train each model with equal amount of data set for each simulation (hardware or software)
VALID_HARDWARE_RUNS = ["_Run_2_", "_Run_8_", "_Run_9_", "_Run_10_", "_Run_11_", "_Run_12_"]
VALID_SOFTWARE_RUNS = ["_rerun_01_", "_rerun_02_", "_rerun_03_", "_rerun_04_", "_rerun_06_", "_rerun_07_"]

def apply_general_wsal_labels(dataframe: pd.DataFrame):
    """apply general labeling on loaded windows security audit logs (e.g. [encrypt copy, encrypt decrypt, encrypt copy] -> [encrypt, encrypt, encrypt])

    Args:
        dataframe (pd.DataFrame): data container which includes loaded windows security audit logs

    Returns:
        pd.DataFrame: general labeled windows security audit logs
    """
    data = dataframe.copy()
    data.loc[data['Labels'].str.contains('copy', regex = False, na = False), 'Labels'] = 'copy'
    data.loc[data['Labels'].str.contains('peertube', regex = False, na = False), 'Labels'] = 'peertube'
    data.loc[data['Labels'].str.contains('programming', regex = False, na = False), 'Labels'] = 'programming'
    data.loc[data['Labels'].str.contains('chatting', regex = False, na = False), 'Labels'] = 'chatting'
    data.loc[data['Labels'].str.contains('mailing', regex = False, na = False), 'Labels'] = 'mailing'
    data.loc[data['Labels'].str.contains('mutillidae', regex = False, na = False), 'Labels'] = 'mutillidae'
    data.loc[data['Labels'].str.contains('encrypt', regex = False, na = False), 'Labels'] = 'encrypt'

    return data

def load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files: pathlib.Path, sim_user_of_interest: str,
                                                                     label_mode: str, time_window_event_grouping: str, system_path_to_store_label_encoding: pathlib.Path):
    """load complete hardware or software simulation run of a specific simulation user based on compressed csv file format

    Args:
        system_path_with_csv_wsal_files (pathlib.Path): system path to load specifc pre-parsed (csv files compressed with gzip) Windows 10 security audit log files from
        sim_user_of_interest (str): simulation user of interest
        label_mode (str): define granularity of behavior labels (two modes possible: general_label_mode, granular_label_mode) -> general label mode includes only high level labels without differentiating between subbehavior patterns (e.g. encrypt -> no differentiation between encrypt copy, decrpyt encrypt and delete)
        time_window_event_grouping (str): size of time windows to group events based on seconds (max. value for time windows 55s)
        system_path_to_store_label_encoding (pathlib.Path): system path to store label encoding 

    Returns:
        pd.DataFrame: loaded and preprocessed windows audit logs
    """
    software_sim_path_tag = "valid_software_sim23"
    hardware_sim_path_tag = "valid_hardware_sim23"

    wsal_files = [entry[2] for entry in os.walk(system_path_with_csv_wsal_files)]
    wsal_files_sim_user_specific = []
    # software sim path
    if(software_sim_path_tag in str(system_path_with_csv_wsal_files)):
        wsal_files_sim_user_specific = [entry for entry in wsal_files[0] if((sim_user_of_interest in entry) and (any(True for substring in VALID_SOFTWARE_RUNS if(substring in entry))))]
        
    # hardware sim path
    elif(hardware_sim_path_tag in str(system_path_with_csv_wsal_files)):
        wsal_files_sim_user_specific = [entry for entry in wsal_files[0] if((sim_user_of_interest in entry) and (any(True for substring in VALID_HARDWARE_RUNS if(substring in entry))))]
        
    loaded_wsal_from_csv_files = pd.DataFrame()
    
    for idx, file in enumerate(wsal_files_sim_user_specific):
        print(idx)
        data = pd.read_csv(pathlib.Path.joinpath(pathlib.Path(system_path_with_csv_wsal_files), file), compression = "gzip")[['SYSTEM_TimeCreated', 'SYSTEM_EventID', 'Labels']]
        loaded_wsal_from_csv_files = pd.concat([loaded_wsal_from_csv_files, data], copy = False, ignore_index = True, axis = 0)
        loaded_wsal_from_csv_files["SYSTEM_TimeCreated"] = pd.to_datetime(loaded_wsal_from_csv_files["SYSTEM_TimeCreated"]).dt.tz_localize(None)
        loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.sort_values(by = "SYSTEM_TimeCreated", ignore_index = True)

    # optional labeling
    if(label_mode == "general_label_mode"):
        loaded_wsal_from_csv_files = apply_general_wsal_labels(dataframe = loaded_wsal_from_csv_files)
    # 82 per client -> total for all machines 91 labels
    # remove default label which indicates no bot behavior incldued
    loaded_wsal_from_csv_files = loaded_wsal_from_csv_files[loaded_wsal_from_csv_files["Labels"].str.contains('no_label', regex = False) == False]

    logging.debug('%s|%s|%s|%s',"Shape before dropping duplicate entries from data set", system_path_with_csv_wsal_files, sim_user_of_interest, loaded_wsal_from_csv_files.shape)

    # drop duplicates from initial file loading
    loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.drop_duplicates()
    
    logging.debug('%s|%s|%s|%s',"Shape after dropping duplicate entries from data set", system_path_with_csv_wsal_files, sim_user_of_interest, loaded_wsal_from_csv_files.shape)

    loaded_wsal_from_csv_files = encodings_wsal.encode_wsal_data_container_time_window_based_event_ids_only(loaded_wsal_from_csv_files, time_window_event_grouping)
    # drop timestamp
    loaded_wsal_from_csv_files.drop('SYSTEM_TimeCreated', inplace=True, axis=1) 
    # generate nummerical data labels
    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform(loaded_wsal_from_csv_files['Labels'])

    # store labeling encoding schema for later ml preprocessing
    label_encoding_name_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
    if(software_sim_path_tag in str(system_path_with_csv_wsal_files)):
        pd.DataFrame([label_encoding_name_mapping]).to_csv(pathlib.Path.joinpath(system_path_to_store_label_encoding, software_sim_path_tag + "_" + sim_user_of_interest + "_" + "label_encoding" + ".csv"))
    elif(hardware_sim_path_tag in str(system_path_with_csv_wsal_files)):
        pd.DataFrame([label_encoding_name_mapping]).to_csv(pathlib.Path.joinpath(system_path_to_store_label_encoding, hardware_sim_path_tag + "_" + sim_user_of_interest + "_" + "label_encoding" + ".csv"))

    y_data_software_sim = pd.Series(data=encoded_labels, name = 'Labels')
    loaded_wsal_from_csv_files.drop('Labels', axis=1, inplace=True)
    loaded_wsal_from_csv_files['Labels'] = y_data_software_sim.astype(int).values
    loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.reset_index(drop = True)

    return loaded_wsal_from_csv_files 

def save_non_zero_count_columns_dataframe(dataframe: pd.DataFrame, file_to_write_results: pathlib.Path):
    """write number of dataframe non-zero column values to text file 

    Args:
        dataframe (pd.DataFrame): dataframe which should be analyzed related to non-zero column values
        file_to_write_results (pathlib.Path): system path to store the non-zero count of column values as text file
    """
    # check count of non-zero values in dataframe cols (label column excluded)
    info_as_string_value = "shape of dataframe: "+ str(dataframe.shape) + "\n" + "count of non-zero values in dataframe columns:" + "\n" + dataframe.fillna(0).iloc[:,:-1].astype(bool).sum(axis=0).to_string()
    file_to_write_results.touch()
    file_to_write_results.write_text(info_as_string_value)

def limit_memory_usage(maxsize: int): 
    """set limit of RAM to use (works only with Linux)

    Args:
        maxsize (int): max RAM usage in bytes
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

def main(system_path_gzip_folder_hardware_sim: str = None, system_path_gzip_folder_software_sim: str = None, system_path_to_store_ml_results: str = None, sim_user_of_interest: str = None, label_mode: str = "general_label_mode", time_windows_event_grouping: str = "s",
         max_ram_usage: int = 0, system_path_to_save_encoded_data: str = "skip_saving_encoding", load_pre_encoded_dummy_data: str = "dont_load_dummy_data"):
    
    logging.basicConfig(filename=pathlib.Path(__file__).with_name('warnings.log'), level = logging.DEBUG, format = '%(asctime)s - %(levelname)s - %(message)s', datefmt = "%d/%m/%Y %H:%M:%S")
    logging.captureWarnings(True)
    limit_memory_usage(max_ram_usage)

    system_path_to_store_results_with_sub_folder = pathlib.Path.joinpath(pathlib.Path(system_path_to_store_ml_results), sim_user_of_interest)
    # create result sub fold if it does not exist (separated by simulation user)
    if(not system_path_to_store_results_with_sub_folder.is_dir()):
        pathlib.Path.mkdir(system_path_to_store_results_with_sub_folder)

    encoding_name = time_windows_event_grouping + "_time_windows_size_" + label_mode 

    if(time_windows_event_grouping == "s"):
        # only replace first occurance of 's' in encoding name
        encoding_name = encoding_name.replace("s_", "1s_", 1)

    ####################################
    #                                  #
    # loading hardware & software data #
    #                                  #
    ####################################
    if(load_pre_encoded_dummy_data == "dont_load_dummy_data"):
        software_sim_data = load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files = pathlib.Path(system_path_gzip_folder_software_sim), sim_user_of_interest = sim_user_of_interest, label_mode = label_mode, 
                                                                                             time_window_event_grouping = time_windows_event_grouping, system_path_to_store_label_encoding = system_path_to_store_results_with_sub_folder)
        # save encoded data for multiple test runs to save system runtime
        if(system_path_to_save_encoded_data != "skip_saving_encoding"):
            file_name_save_encoded_data = "pre_encoded_data_software_simulation" + "_" + sim_user_of_interest + "_" + encoding_name + ".gz"
            software_sim_data.to_csv(pathlib.Path(pathlib.Path.joinpath(pathlib.Path(system_path_to_save_encoded_data), file_name_save_encoded_data)), index = False, compression = "gzip")
        
        save_non_zero_count_columns_dataframe(software_sim_data, pathlib.Path.joinpath(system_path_to_store_results_with_sub_folder, "software_dataframe_" + sim_user_of_interest + "non_zero_column_value_count" + ".txt"))
    
        hardware_sim_data = load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files = pathlib.Path(system_path_gzip_folder_hardware_sim), sim_user_of_interest = sim_user_of_interest, label_mode = label_mode,
                                                                                             time_window_event_grouping = time_windows_event_grouping, system_path_to_store_label_encoding = system_path_to_store_results_with_sub_folder)
        
        save_non_zero_count_columns_dataframe(hardware_sim_data, pathlib.Path.joinpath(system_path_to_store_results_with_sub_folder, "hardware_dataframe_" + sim_user_of_interest + "non_zero_column_value_count" + ".txt"))

        # save encoded data for multiple test runs to save system runtime
        if(system_path_to_save_encoded_data != "skip_saving_encoding"):
            file_name_save_encoded_data = "pre_encoded_data_hardware_simulation" + "_" + sim_user_of_interest + "_" + encoding_name + ".gz"
            hardware_sim_data.to_csv(pathlib.Path(pathlib.Path.joinpath(pathlib.Path(system_path_to_save_encoded_data), file_name_save_encoded_data)), index = False, compression = "gzip")
    
    elif(load_pre_encoded_dummy_data == "load_dummy_data"):
        pre_encoded_data_path_hardware_software_data_containing_all_files = pathlib.Path.joinpath(pathlib.Path(pathlib.Path(__file__).with_name('machine_learning')), "pre_encoded_data")

        # specific time window for encoding
        time_windows_size = time_windows_event_grouping
        if(time_windows_event_grouping == "s"):
            time_windows_size = "1s"

        hardware_pre_encoded_data_file_path = [file_name for file_name in pre_encoded_data_path_hardware_software_data_containing_all_files.iterdir() if((sim_user_of_interest in str(file_name)) and ("hardware_simulation" in str(file_name)) and (time_windows_size in str(file_name)))][0]
        software_pre_encoded_data_file_path = [file_name for file_name in pre_encoded_data_path_hardware_software_data_containing_all_files.iterdir() if((sim_user_of_interest in str(file_name)) and ("software_simulation" in str(file_name)) and (time_windows_size in str(file_name)))][0]
        
        hardware_sim_data = pd.read_csv(filepath_or_buffer = hardware_pre_encoded_data_file_path, compression = "gzip")
        software_sim_data = pd.read_csv(filepath_or_buffer = software_pre_encoded_data_file_path, compression = "gzip")
    
    ###########################################################
    #                                                         #
    # non-scaled inter evaluation of hardware & software data #
    #                                                         #
    ###########################################################
    # if necessary add zero value column to of the the dataframes
    software_sim_data_no_scaling = software_sim_data.copy()
    hardware_sim_data_no_scaling = hardware_sim_data.copy()
    software_sim_data_no_scaling['Hardware_or_Software'] = "Software"
    hardware_sim_data_no_scaling['Hardware_or_Software'] = "Hardware"

    combined_data_set = pd.concat([hardware_sim_data_no_scaling, software_sim_data_no_scaling], ignore_index = True, copy = False, axis = 0)
    combined_data_set.fillna(0, inplace = True)

    hardware_sim_data_no_scaling = combined_data_set.loc[combined_data_set["Hardware_or_Software"] == "Hardware"].copy()
    software_sim_data_no_scaling = combined_data_set.loc[combined_data_set["Hardware_or_Software"] == "Software"].copy()
    hardware_sim_data_no_scaling.drop("Hardware_or_Software", inplace = True, axis = 1)
    software_sim_data_no_scaling.drop("Hardware_or_Software", inplace = True, axis = 1)

    X_train_software_sim_data_no_scaling, X_test_software_sim_data_no_scaling, y_train_software_sim_data_no_scaling, y_test_software_sim_data_no_scaling = train_test_split(software_sim_data_no_scaling.loc[:, software_sim_data_no_scaling.columns != "Labels"].values, software_sim_data_no_scaling["Labels"].values, test_size = 0.5, random_state = 42, stratify = software_sim_data_no_scaling["Labels"].values)

    X_train_hardware_sim_data_no_scaling, X_test_hardware_sim_data_no_scaling, y_train_hardware_sim_data_no_scaling, y_test_hardware_sim_data_no_scaling = train_test_split(hardware_sim_data_no_scaling.loc[:, hardware_sim_data_no_scaling.columns != "Labels"].values, hardware_sim_data_no_scaling["Labels"].values, test_size = 0.5, random_state = 42, stratify = hardware_sim_data_no_scaling["Labels"].values)

    data_set_name = "hardware_test_data_software_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    
    classification_ml_wsal.evaluate_model(X_train = X_train_software_sim_data_no_scaling,
                                          X_test = X_test_hardware_sim_data_no_scaling,
                                          y_train = y_train_software_sim_data_no_scaling,
                                          y_test = y_test_hardware_sim_data_no_scaling,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("inter evaluation software and hardware simulation -> train data: software simulation data")
    print("inter evaluation software and hardware simulation -> test data: hardware simulation data")
    print("inter evaluation software and hardware simulation -> train data (software simulation data) -> unique labels: " + str(set(y_train_software_sim_data_no_scaling)))
    print("inter evaluation software and hardware simulation -> test data (hardware simulation data) -> unique labels: " + str(set(y_test_hardware_sim_data_no_scaling)))
    print("inter evaluation software and hardware simulation -> train data (software simulation data) -> shape: " + str(X_train_software_sim_data_no_scaling.shape))
    print("inter evaluation software and hardware simulation -> test data (hardware simulation data) -> shape: " + str(X_test_hardware_sim_data_no_scaling.shape))
    
    data_set_name = "software_test_data_hardware_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_hardware_sim_data_no_scaling,
                                          X_test = X_test_software_sim_data_no_scaling,
                                          y_train = y_train_hardware_sim_data_no_scaling,
                                          y_test = y_test_software_sim_data_no_scaling,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("inter evaluation software and hardware simulation -> train data: hardware simulation data")
    print("inter evaluation software and hardware simulation -> test data: software simulation data")
    print("inter evaluation software and hardware simulation -> train data (hardware simulation data) -> unique labels: " + str(set(y_train_hardware_sim_data_no_scaling)))
    print("inter evaluation software and hardware simulation -> test data (software simulation data) -> unique labels: " + str(set(y_test_software_sim_data_no_scaling)))
    print("inter evaluation software and hardware simulation -> train data (hardware simulation data) -> shape: " + str(X_train_hardware_sim_data_no_scaling.shape))
    print("inter evaluation software and hardware simulation -> test data (software simulation data) -> shape: " + str(X_test_software_sim_data_no_scaling.shape))

    ##################################################################
    #                                                                #
    # prepare min-max-scaled evaluations of hardware & software data #
    #                                                                #
    ##################################################################
    # min-max normalization
    scaler_min_max = MinMaxScaler()

    # hardware sim standalone evaluation
    min_max_scaled_hardware_sim_data = hardware_sim_data.copy()
    data_set_name = "min_max_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_min_max_scaled_hardware_sim_data = [idx for idx, value in enumerate(min_max_scaled_hardware_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int -> due to scaling
    min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data] = min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data].astype(float)

    min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data] = scaler_min_max.fit_transform(min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data].values)
    
    # software simulation data set standalone evaluation
    min_max_scaled_software_sim_data = software_sim_data.copy()
    data_set_name = "min_max_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_min_max_scaled_software_sim_data = [idx for idx, value in enumerate(min_max_scaled_software_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int
    min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data] = min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data].astype(float)

    min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data] = scaler_min_max.fit_transform(min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data].values)

    ###############################################################
    #                                                             #
    # min-max-scaled inter evaluation of hardware & software data #
    #                                                             #
    ###############################################################
    # prepare data for combine (hardware sim data & software sim data ml evaluation with scaled data values)
    combined_data_set_min_max_scaled = combined_data_set.copy()
    # label and hardware_or_software cols excluded
    col_of_interest_min_max_scaled = [idx for idx, value in enumerate(combined_data_set_min_max_scaled.columns) if((value != "Labels") and (value != "Hardware_or_Software"))]

    # scaled data will be in float format instead of int
    combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled] = combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled].astype(float)

    combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled] = scaler_min_max.fit_transform(combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled].values)

    hardware_sim_combined_min_max_scaled = combined_data_set_min_max_scaled.loc[combined_data_set_min_max_scaled["Hardware_or_Software"] == "Hardware"]
    software_sim_combined_min_max_scaled = combined_data_set_min_max_scaled.loc[combined_data_set_min_max_scaled["Hardware_or_Software"] == "Software"]
    hardware_sim_combined_min_max_scaled.drop("Hardware_or_Software", inplace = True, axis = 1)
    software_sim_combined_min_max_scaled.drop("Hardware_or_Software", inplace = True, axis = 1)

    X_train_software_sim_combined_min_max_scaled, X_test_software_sim_combined_min_max_scaled, y_train_software_sim_combined_min_max_scaled, y_test_software_sim_combined_min_max_scaled = train_test_split(software_sim_combined_min_max_scaled.loc[:, software_sim_combined_min_max_scaled.columns != "Labels"].values, software_sim_combined_min_max_scaled["Labels"].values, test_size = 0.5, random_state = 42, stratify = software_sim_combined_min_max_scaled["Labels"].values)

    X_train_hardware_sim_combined_min_max_scaled, X_test_hardware_sim_combined_min_max_scaled, y_train_hardware_sim_combined_min_max_scaled, y_test_hardware_sim_combined_min_max_scaled = train_test_split(hardware_sim_combined_min_max_scaled.loc[:, hardware_sim_combined_min_max_scaled.columns != "Labels"].values, hardware_sim_combined_min_max_scaled["Labels"].values, test_size = 0.5, random_state = 42, stratify = hardware_sim_combined_min_max_scaled["Labels"].values)

    data_set_name = "min_max_scaled_hardware_test_data_software_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_software_sim_combined_min_max_scaled,
                                          X_test = X_test_hardware_sim_combined_min_max_scaled ,
                                          y_train = y_train_software_sim_combined_min_max_scaled,
                                          y_test = y_test_hardware_sim_combined_min_max_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("inter evaluation software and hardware simulation min-max-scaled -> train data: software simulation data")
    print("inter evaluation software and hardware simulation min-max-scaled -> test data: hardware simulation data")
    print("inter evaluation software and hardware simulation min-max-scaled -> train data (software simulation data) -> unique labels: " + str(set(y_train_software_sim_combined_min_max_scaled)))
    print("inter evaluation software and hardware simulation min-max-scaled -> test data (hardware simulation data) -> unique labels: " + str(set(y_test_hardware_sim_combined_min_max_scaled)))
    print("inter evaluation software and hardware simulation min-max-scaled -> train data (software simulation data) -> shape: " + str(X_train_software_sim_combined_min_max_scaled.shape))
    print("inter evaluation software and hardware simulation min-max-scaled -> test data (hardware simulation data) -> shape: " + str(X_test_hardware_sim_combined_min_max_scaled.shape))
    
    data_set_name = "min_max_scaled_software_test_data_hardware_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_hardware_sim_combined_min_max_scaled,
                                          X_test = X_test_software_sim_combined_min_max_scaled,
                                          y_train = y_train_hardware_sim_combined_min_max_scaled,
                                          y_test = y_test_software_sim_combined_min_max_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("inter evaluation software and hardware simulation min-max-scaled -> train data: hardware simulation data")
    print("inter evaluation software and hardware simulation min-max-scaled -> test data: software simulation data")
    print("inter evaluation software and hardware simulation min-max-scaled -> train data (hardware simulation data) -> unique labels: " + str(set(y_train_hardware_sim_combined_min_max_scaled)))
    print("inter evaluation software and hardware simulation min-max-scaled -> test data (software simulation data) -> unique labels: " + str(set(y_test_software_sim_combined_min_max_scaled)))
    print("inter evaluation software and hardware simulation min-max-scaled -> train data (hardware simulation data) -> shape: " + str(X_train_hardware_sim_combined_min_max_scaled.shape))
    print("inter evaluation software and hardware simulation min-max-scaled -> test data (software simulation data) -> shape: " + str(X_test_software_sim_combined_min_max_scaled.shape))

    ###########################################################
    #                                                         #
    # non-scaled intra evaluation of hardware & software data #
    #                                                         #
    ###########################################################
    # software simulation data not scaled
    X_train_software_sim_not_scaled, X_test_software_sim_not_scaled, y_train_software_sim_not_scaled, y_test_software_sim_not_scaled = train_test_split(software_sim_data.loc[:, software_sim_data.columns != "Labels"].values, software_sim_data["Labels"].values, test_size = 0.5, random_state = 42, stratify = software_sim_data["Labels"].values)
    data_set_name = "software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_software_sim_not_scaled,
                                          X_test = X_test_software_sim_not_scaled,
                                          y_train = y_train_software_sim_not_scaled,
                                          y_test = y_test_software_sim_not_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("intra evaluation software simulation not scaled -> train data: software simulation data")
    print("intra evaluation software simulation not scaled -> test data: software simulation data")
    print("intra evaluation software simulation not scaled -> train data (software simulation data) -> unique labels: " + str(set(y_train_software_sim_not_scaled)))
    print("intra evaluation software simulation not scaled -> test data (software simulation data) -> unique labels: " + str(set(y_test_software_sim_not_scaled)))
    print("intra evaluation software simulation not scaled -> train data (software simulation data) -> shape: " + str(X_train_software_sim_not_scaled.shape))
    print("intra evaluation software simulation not scaled -> test data (software simulation data) -> shape: " + str(X_test_software_sim_not_scaled.shape))
    
    # hardware simulation data not scaled
    X_train_hardware_sim_not_scaled, X_test_hardware_sim_not_scaled, y_train_hardware_sim_not_scaled, y_test_hardware_sim_not_scaled = train_test_split(hardware_sim_data.loc[:, hardware_sim_data.columns != "Labels"].values, hardware_sim_data["Labels"].values, test_size = 0.5, random_state = 42, stratify = hardware_sim_data["Labels"].values)
    data_set_name = "hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_hardware_sim_not_scaled,
                                          X_test = X_test_hardware_sim_not_scaled,
                                          y_train = y_train_hardware_sim_not_scaled,
                                          y_test = y_test_hardware_sim_not_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("intra evaluation hardware simulation not scaled -> train data: hardware simulation data")
    print("intra evaluation hardware simulation not scaled -> test data: hardware simulation data")
    print("intra evaluation hardware simulation not scaled -> train data (hardware simulation data) -> unique labels: " + str(set(y_train_hardware_sim_not_scaled)))
    print("intra evaluation hardware simulation not scaled -> test data (hardware simulation data) -> unique labels: " + str(set(y_test_hardware_sim_not_scaled)))
    print("intra evaluation hardware simulation not scaled -> train data (hardware simulation data) -> shape: " + str(X_train_hardware_sim_not_scaled.shape))
    print("intra evaluation hardware simulation not scaled -> test data (hardware simulation data) -> shape: " + str(X_test_hardware_sim_not_scaled.shape))

    ###############################################################
    #                                                             #
    # min-max-scaled intra evaluation of hardware & software data #
    #                                                             #
    ###############################################################
    # software simulation data min-max-scaled
    X_train_software_sim_min_max_scaled, X_test_software_sim_min_max_scaled, y_train_software_sim_min_max_scaled, y_test_software_sim_min_max_scaled = train_test_split(min_max_scaled_software_sim_data.loc[:, min_max_scaled_software_sim_data.columns != "Labels"].values, min_max_scaled_software_sim_data["Labels"].values, test_size = 0.5, random_state = 42, stratify = min_max_scaled_software_sim_data["Labels"].values)
    data_set_name = "min_max_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_software_sim_min_max_scaled,
                                          X_test = X_test_software_sim_min_max_scaled,
                                          y_train = y_train_software_sim_min_max_scaled,
                                          y_test = y_test_software_sim_min_max_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("intra evaluation software simulation min-max-scaled -> train data: software simulation data")
    print("intra evaluation software simulation min-max-scaled -> test data: software simulation data")
    print("intra evaluation software simulation min-max-scaled -> train data (software simulation data) -> unique labels: " + str(set(y_train_software_sim_min_max_scaled)))
    print("intra evaluation software simulation min-max-scaled -> test data (software simulation data) -> unique labels: " + str(set(y_test_software_sim_min_max_scaled)))
    print("intra evaluation software simulation min-max-scaled -> train data (software simulation data) -> shape: " + str(X_train_software_sim_min_max_scaled.shape))
    print("intra evaluation software simulation min-max-scaled -> test data (software simulation data) -> shape: " + str(X_test_software_sim_min_max_scaled.shape))
    
    # hardware simulation data min-max-scaled
    X_train_hardware_sim_min_max_scaled, X_test_hardware_sim_min_max_scaled, y_train_hardware_sim_min_max_scaled, y_test_hardware_sim_min_max_scaled = train_test_split(min_max_scaled_hardware_sim_data.loc[:, min_max_scaled_hardware_sim_data.columns != "Labels"].values, min_max_scaled_hardware_sim_data["Labels"].values, test_size = 0.5, random_state = 42, stratify = min_max_scaled_hardware_sim_data["Labels"].values)
    data_set_name = "min_max_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train = X_train_hardware_sim_min_max_scaled,
                                          X_test = X_test_hardware_sim_min_max_scaled,
                                          y_train = y_train_hardware_sim_min_max_scaled,
                                          y_test = y_test_hardware_sim_min_max_scaled,
                                          encoding_name = encoding_name,
                                          data_set_name = data_set_name,
                                          path_to_store_results = system_path_to_store_results_with_sub_folder)
    
    print("intra evaluation software hardware min-max-scaled -> train data: hardware simulation data")
    print("intra evaluation software hardware min-max-scaled -> test data: hardware simulation data")
    print("intra evaluation software hardware min-max-scaled -> train data (hardware simulation data) -> unique labels: " + str(set(y_train_hardware_sim_min_max_scaled)))
    print("intra evaluation software hardware min-max-scaled -> test data (hardware simulation data) -> unique labels: " + str(set(y_test_hardware_sim_min_max_scaled)))
    print("intra evaluation software hardware min-max-scaled -> train data (hardware simulation data) -> shape: " + str(X_train_hardware_sim_min_max_scaled.shape))
    print("intra evaluation software hardware min-max-scaled -> test data (hardware simulation data) -> shape: " + str(X_test_hardware_sim_min_max_scaled.shape))

    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage:
        ''')%(NAME, VERSION)))
        
        parser.add_argument('system_path_gzip_folder_hardware_sim', type = str, help = "system path which includes compressed (gzip) Windows 10 security audit log files for hardware simulation (type:str) (e.g., /home/path/to/hardware_data)")
        parser.add_argument('system_path_gzip_folder_software_sim', type = str, help = "system path which includes compressed (gzip) Windows 10 security audit log files for software simulation (type:str) (e.g., /home/path/to/software_data)")
        parser.add_argument('path_to_store_ml_results', type = str, help = "system path which includes machine learning results (type:str) (e.g., /home/user/ml_results)")
        parser.add_argument('sim_user_of_interest', type = str, help = "simulation user of interest (type:str) (e.g., SimUser001)")
        parser.add_argument('label_mode', type = str, help = "data labeling model (type:str) (choose between: general_label_mode, granular_label_mode)")
        parser.add_argument('time_window_size_event_grouping', type = str, help = "size of time windows for event grouping in seconds (type:str) (e.g., s, 2s, 3s)")
        parser.add_argument('max_ram_usage', type = int, help = "define max ram usage of this script in bytes")
        parser.add_argument('system_path_to_save_encoded_data', type = str, help = "save  values: system path, to store encoded data | skip_saving_encoding, to not save encoded data")
        parser.add_argument('load_pre_encoded_dummy_data', type=str, help="load pre-encoded dummy data prepared by paper authors | start loading if value is: load_dummy_data ; skip loading if value is: dont_load_dummy_data (type:str)")
        args = parser.parse_args()
        system_path_gzip_folder_hardware_sim_cmd = args.system_path_gzip_folder_hardware_sim
        system_path_gzip_folder_software_sim_cmd = args.system_path_gzip_folder_software_sim
        path_to_store_ml_results_cmd = args.path_to_store_ml_results
        sim_user_of_interest_cmd = args.sim_user_of_interest
        label_mode_cmd = args.label_mode
        max_ram_usage_cmd = args.max_ram_usage
        time_window_size_event_grouping_cmd = args.time_window_size_event_grouping
        system_path_to_save_encoded_data_cmd = args.system_path_to_save_encoded_data
        load_pre_encoded_dummy_data_cmd = args.load_pre_encoded_dummy_data

        return_code = main(system_path_gzip_folder_hardware_sim_cmd, system_path_gzip_folder_software_sim_cmd, path_to_store_ml_results_cmd, sim_user_of_interest_cmd, label_mode_cmd, time_window_size_event_grouping_cmd, max_ram_usage_cmd, system_path_to_save_encoded_data_cmd, load_pre_encoded_dummy_data_cmd)
        quit(return_code)
    else:
        main()