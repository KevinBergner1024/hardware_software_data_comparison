import argparse
import textwrap
import pandas as pd
import pathlib 
import numpy as np
import os
import logging
import warnings
import resource

from machine_learning import classification_ml_wsal
from machine_learning import encodings_wsal
from process_wal import process_wal
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split

NAME = "WSAL MAIN MACHINE LEARNING SCRIPT"
VERSION = "1.10"
CMD_MODE_ENABLED = True

# NOTICE: software run has one more file _rerun_09_ which is excluded at this point to train each model with equal amount of data set for each simulation (hardware or software)
VALID_HARDWARE_RUNS = ["_Run_2_", "_Run_8_", "_Run_9_", "_Run_10_", "_Run_11_", "_Run_12_"]
VALID_SOFTWARE_RUNS = ["_rerun_01_", "_rerun_02_", "_rerun_03_", "_rerun_04_", "_rerun_06_", "_rerun_07_"]

def apply_general_wsal_labels(dataframe:pd.DataFrame):
    """aplly general labeling on loaded windows security audit logs (e.g. [encrypt copy, encrypt decrypt, encrypt copy] -> [encrypt, encrypt, encrypt])

    Args:
        dataframe (pd.DataFrame): data container which includes loaded windows security audit logs

    Returns:
        pd.DataFrame: general labeled windows security audit logs
    """
    data = dataframe.copy()
    data.loc[data['Labels'].str.contains('copy', regex=False, na=False), 'Labels'] = 'copy'
    data.loc[data['Labels'].str.contains('peertube', regex=False, na=False), 'Labels'] = 'peertube'
    data.loc[data['Labels'].str.contains('programming', regex=False, na=False), 'Labels'] = 'programming'
    data.loc[data['Labels'].str.contains('chatting', regex=False, na=False), 'Labels'] = 'chatting'
    data.loc[data['Labels'].str.contains('mailing', regex=False, na=False), 'Labels'] = 'mailing'
    data.loc[data['Labels'].str.contains('mutillidae', regex=False, na=False), 'Labels'] = 'mutillidae'
    data.loc[data['Labels'].str.contains('encrypt', regex=False, na=False), 'Labels'] = 'encrypt'

    return data

def load_iteration_time(iteration_times_log_file_path:pathlib.Path):
    # load iteration timestamps
    iteration_timestamps = pathlib.Path(iteration_times_log_file_path).read_text()
    iteration_timestamps = [ele.split(",") for ele in iteration_timestamps.split("\n")]
    iteration_timestamps_df = pd.DataFrame(iteration_timestamps, columns=["File_Name", "Start_Timestamp", "End_Timestamp"])
    
    iteration_timestamps_df["Start_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["Start_Timestamp"]).dt.tz_localize(None) 
    iteration_timestamps_df["End_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["End_Timestamp"]).dt.tz_localize(None) 

    return iteration_timestamps_df

def load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files:pathlib.Path, sim_user_of_interest:str, label_mode:str, time_window_event_grouping:str, system_path_to_store_label_encoding:pathlib.Path,
                                                                     iteration_timestamps:pathlib.Path):
    """laod complete hardware or software simulation run of a specific simulation user based on compressed csv file format

    Args:
        system_path_with_csv_wsal_files (pathlib.Path): system path to load specifc pre-parsed (csv files compressed with gzip) windows audit log files from
        sim_user_of_interest (str): sim user of interest
        label_mode (str): define granularity of behavior labels (two modes possible: general_label_mode, granular_label_mode) -> general label mode includes only high level labels without differentiating between subbehavior patterns (e.g. encrypt -> no differentiation between encrypt copy, decrpyt encrypt and delete)
        time_window_event_grouping (str): size of time windows to group events based on seconds (max. value for time windows 55s)
        system_path_to_store_label_encoding (pathlib.Path): system path to store label encoding 

    Returns:
        pd.DataFrame: loaded and preprocessed windows audit logs
    """

    software_sim_path_tag = "valid_software_sim23"
    hardware_sim_path_tag = "valid_hardware_sim23"

    loaded_iteration_timestamps_df = load_iteration_time(iteration_timestamps)

    wsal_files = [entry[2] for entry in os.walk(system_path_with_csv_wsal_files)]
    wsal_files_sim_user_specific = []
    # select data to load for hardware or software sim
    # software sim path
    if(software_sim_path_tag in str(system_path_with_csv_wsal_files)):
        wsal_files_sim_user_specific = [entry for entry in wsal_files[0] if((sim_user_of_interest in entry) and (any(True for substring in VALID_SOFTWARE_RUNS if(substring in entry))))]
        
    # hardware sim path
    elif(hardware_sim_path_tag in str(system_path_with_csv_wsal_files)):
        wsal_files_sim_user_specific = [entry for entry in wsal_files[0] if((sim_user_of_interest in entry) and (any(True for substring in VALID_HARDWARE_RUNS if(substring in entry))))]
        
    loaded_wsal_from_csv_files = pd.DataFrame()
    
    for idx, file in enumerate(wsal_files_sim_user_specific):
        print(idx)
        data = pd.read_csv(pathlib.Path.joinpath(pathlib.Path(system_path_with_csv_wsal_files), file), compression="gzip")[['SYSTEM_TimeCreated', 'SYSTEM_EventID', 'Labels']]
        
        # START:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files 
        #data["SYSTEM_TimeCreated"] = pd.to_datetime(data["SYSTEM_TimeCreated"]).dt.tz_localize(None)
        #data = data.sort_values(by="SYSTEM_TimeCreated", ignore_index=True)

        #start = loaded_iteration_timestamps_df.loc[loaded_iteration_timestamps_df["File_Name"] == file]['Start_Timestamp'].values[0] 
        #end = loaded_iteration_timestamps_df.loc[loaded_iteration_timestamps_df["File_Name"] == file]['End_Timestamp'].values[0]
        #data = data.loc[(data["SYSTEM_TimeCreated"] >= start) & (data["SYSTEM_TimeCreated"] <= end)]
        # END:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files

        loaded_wsal_from_csv_files = pd.concat([loaded_wsal_from_csv_files, data], copy=False, ignore_index=True, axis=0)
        loaded_wsal_from_csv_files["SYSTEM_TimeCreated"] = pd.to_datetime(loaded_wsal_from_csv_files["SYSTEM_TimeCreated"]).dt.tz_localize(None)
        loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.sort_values(by="SYSTEM_TimeCreated", ignore_index=True)

    # optional labeling
    if(label_mode == "general_label_mode"):
        loaded_wsal_from_csv_files = apply_general_wsal_labels(dataframe=loaded_wsal_from_csv_files)
    # 82 per client -> total for all machines 91 labels
    # remove default label which indicates no bot behavior incldued
    loaded_wsal_from_csv_files = loaded_wsal_from_csv_files[loaded_wsal_from_csv_files["Labels"].str.contains('no_label', regex=False) == False]

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
    # this container should be used to work with
    loaded_wsal_from_csv_files['Labels'] = y_data_software_sim.astype(int).values
    # drop duplicates after preprocessing of the encoded data set - disabled 10.02.2025
    # loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.drop_duplicates()
    loaded_wsal_from_csv_files = loaded_wsal_from_csv_files.reset_index(drop=True)

    return loaded_wsal_from_csv_files 

def save_non_zero_count_columns_dataframe(dataframe:pd.DataFrame, file_to_write_results:pathlib.Path):
    """write count of dataframe non-zero column values to text file 

    Args:
        dataframe (pd.DataFrame): dataframe which should be analyzed related to non-zero column values
        file_to_write_results (pathlib.Path): system path to store the non-zero count of column values as text file
    """
    # check count of non-zero values in dataframe cols (label column excluded)
    info_as_string_value = "shape of dataframe: "+ str(dataframe.shape) + "\n" + "count of non-zero values in dataframe columns:" + "\n" + dataframe.fillna(0).iloc[:,:-1].astype(bool).sum(axis=0).to_string()
    file_to_write_results.touch()
    file_to_write_results.write_text(info_as_string_value)

def limit_memory(maxsize): 
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

def main(system_path_gzip_folder_hardware_sim:str=None, system_path_gzip_folder_software_sim:str=None, system_path_to_store_ml_results:str=None, sim_user_of_interest:str=None, label_mode:str="general_label_mode", time_windows_event_grouping:str="s",
         cross_validation_mode_cmd:str="normal_cv_mode", iteration_timestamp_hardware_simulation:str=None, iteration_timestamp_software_simulation:str=None, system_path_to_save_encoded_data:str= "skip"):
    
    logging.basicConfig(filename=pathlib.Path(__file__).with_name('warnings.log'), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
    logging.captureWarnings(True)
    #warnings.filterwarnings('ignore')

    # check if result folder exists
    system_path_to_store_results_with_sub_folder = pathlib.Path.joinpath(pathlib.Path(system_path_to_store_ml_results), sim_user_of_interest)
    # create result sub fold if it does not exist -> clear seperation of result files for different simulation user
    if(not system_path_to_store_results_with_sub_folder.is_dir()):
        pathlib.Path.mkdir(system_path_to_store_results_with_sub_folder)

    encoding_name = time_windows_event_grouping + "_time_windows_size_" + label_mode 

    if(time_windows_event_grouping == "s"):
        # only replace first occurance of 's' in encoding name
        encoding_name = encoding_name.replace("s_", "1s_", 1)
    
    ############################### start load intiial sware simulation setup ###############################
    software_sim_data = load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files=pathlib.Path(system_path_gzip_folder_software_sim), sim_user_of_interest=sim_user_of_interest, label_mode=label_mode,
                                                                                         time_window_event_grouping=time_windows_event_grouping, system_path_to_store_label_encoding=system_path_to_store_results_with_sub_folder,
                                                                                         iteration_timestamps=pathlib.Path(iteration_timestamp_software_simulation))
    # save encoded data for multiple test runs to save system runtime
    if(system_path_to_save_encoded_data != "skip"):
        file_name_save_encoded_data = "pre_encoded_data_software_simulation" + "_" + sim_user_of_interest + "_" + encoding_name + ".gz"
        software_sim_data.to_csv(pathlib.Path(pathlib.Path.joinpath(pathlib.Path(system_path_to_save_encoded_data), file_name_save_encoded_data)), index=False, compression="gzip")
    
    save_non_zero_count_columns_dataframe(software_sim_data, pathlib.Path.joinpath(system_path_to_store_results_with_sub_folder, "software_dataframe_" + sim_user_of_interest + "non_zero_column_value_count" + ".txt"))
    data_set_name = "software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.run_kfold_cross(X=software_sim_data.loc[:, software_sim_data.columns != "Labels"].values,
                                           y=software_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("cross-validation software simulation data without data scaling -> unique labels: " + str(software_sim_data['Labels'].unique()))
    print("cross-validation software simulation data without data scaling -> dataframe shape without duplicate entries: " + str(software_sim_data.shape))
    print("cross-validation software simulation data without data scaling -> dataframe columns: " + str(list(software_sim_data.columns)))
    ############################### end load intiial software simulation setup ###############################

    ############################### start load intiial hardware simulation setup ###############################
    hardware_sim_data = load_simuser_specific_data_set_all_runs_of_a_complete_simulation(system_path_with_csv_wsal_files=pathlib.Path(system_path_gzip_folder_hardware_sim), sim_user_of_interest=sim_user_of_interest, label_mode=label_mode,
                                                                                         time_window_event_grouping=time_windows_event_grouping, system_path_to_store_label_encoding=system_path_to_store_results_with_sub_folder,
                                                                                         iteration_timestamps=pathlib.Path(iteration_timestamp_hardware_simulation))

    # save encoded data for multiple test runs to save system runtime
    if(system_path_to_save_encoded_data != "skip"):
        file_name_save_encoded_data = "pre_encoded_data_hardware_simulation" + "_" + sim_user_of_interest + "_" + encoding_name + ".gz"
        hardware_sim_data.to_csv(pathlib.Path(pathlib.Path.joinpath(pathlib.Path(system_path_to_save_encoded_data), file_name_save_encoded_data)), index=False, compression="gzip")
    
    save_non_zero_count_columns_dataframe(hardware_sim_data, pathlib.Path.joinpath(system_path_to_store_results_with_sub_folder, "hardware_dataframe_" + sim_user_of_interest + "non_zero_column_value_count" + ".txt"))
    data_set_name = "hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.run_kfold_cross(X=hardware_sim_data.loc[:, hardware_sim_data.columns != "Labels"].values,
                                           y=hardware_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("cross-validation hardware simulation data without data scaling -> unique labels: " + str(hardware_sim_data['Labels'].unique()))
    print("cross-validation hardware simulation data without data scaling -> dataframe shape without duplicate entries: " + str(hardware_sim_data.shape))
    print("cross-validation hardware simulation data without data scaling -> dataframe columns: " + str(list(hardware_sim_data.columns)))
    ############################### end load intiial hardware simulation setup ###############################

    ############################### start train/test with hardware data/ software data split (simulation environment split) ###############################
    # if necessary add zero value column to of the the dataframes
    software_sim_data_no_scaling = software_sim_data.copy()
    hardware_sim_data_no_scaling = hardware_sim_data.copy()
    software_sim_data_no_scaling['Hardware_or_Software'] = "Software"
    hardware_sim_data_no_scaling['Hardware_or_Software'] = "Hardware"
    combined_data_set = pd.concat([hardware_sim_data_no_scaling, software_sim_data_no_scaling], ignore_index=True, copy=False, axis=0)
    combined_data_set.fillna(0, inplace=True)

    hardware_sim_data_no_scaling = combined_data_set.loc[combined_data_set["Hardware_or_Software"] == "Hardware"].copy()
    software_sim_data_no_scaling = combined_data_set.loc[combined_data_set["Hardware_or_Software"] == "Software"].copy()
    hardware_sim_data_no_scaling.drop("Hardware_or_Software", inplace=True, axis=1)
    software_sim_data_no_scaling.drop("Hardware_or_Software", inplace=True, axis=1)

    data_set_name = "hardware_test_data_software_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    
    classification_ml_wsal.evaluate_model(X_train=software_sim_data_no_scaling.loc[:, software_sim_data_no_scaling.columns != "Labels"].values,
                                          X_test=hardware_sim_data_no_scaling.loc[:, hardware_sim_data_no_scaling.columns != "Labels"].values,
                                          y_train=software_sim_data_no_scaling['Labels'].values,
                                          y_test=hardware_sim_data_no_scaling['Labels'].values,
                                          encoding_name=encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation -> train data: software simulation data")
    print("combined evaluation software and hardware simulation -> test data: hardware simulation data")
    print("combined evaluation software and hardware simulation -> train data (software simulation data) -> unique labels: " + str(software_sim_data_no_scaling['Labels'].unique()))
    print("combined evaluation software and hardware simulation -> test data (hardware simulation data) -> unique labels: " + str(hardware_sim_data_no_scaling['Labels'].unique()))
    print("combined evaluation software and hardware simulation -> train data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_data_no_scaling.shape))
    print("combined evaluation software and hardware simulation -> test data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_data_no_scaling.shape))
    print("combined evaluation software and hardware simulation -> train data (software simulation data) -> dataframe columns: " + str(list(software_sim_data_no_scaling.columns)))
    print("combined evaluation software and hardware simulation -> test data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_data_no_scaling.columns)))
    
    data_set_name = "software_test_data_hardware_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=hardware_sim_data_no_scaling.loc[:, hardware_sim_data_no_scaling.columns != "Labels"].values,
                                          X_test= software_sim_data_no_scaling.loc[:, software_sim_data_no_scaling.columns != "Labels"].values,
                                          y_train=hardware_sim_data_no_scaling['Labels'].values,
                                          y_test=software_sim_data_no_scaling['Labels'].values,
                                          encoding_name=encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation -> train data: hardware simulation data")
    print("combined evaluation software and hardware simulation -> test data: software simulation data")
    print("combined evaluation software and hardware simulation -> train data (hardware simulation data) -> unique labels: " + str(hardware_sim_data_no_scaling['Labels'].unique()))
    print("combined evaluation software and hardware simulation -> test data (software simulation data) -> unique labels: " + str(software_sim_data_no_scaling['Labels'].unique()))
    print("combined evaluation software and hardware simulation -> train data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_data_no_scaling.shape))
    print("combined evaluation software and hardware simulation -> test data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_data_no_scaling.shape))
    print("combined evaluation software and hardware simulation -> train data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_data_no_scaling.columns)))
    print("combined evaluation software and hardware simulation -> test data (software simulation data) -> dataframe columns: " + str(list(software_sim_data_no_scaling.columns)))
    ############################### end train/test with hardware data/ software data split (simulation environment split) ###############################
    
    ############################### start ml setup for min-max normalized data ###############################
    # min-max normalization
    scaler_min_max = MinMaxScaler()
    # hardware sim standalone evaluation
    min_max_scaled_hardware_sim_data = hardware_sim_data.copy()
    # without label value
    data_set_name = "min_max_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_min_max_scaled_hardware_sim_data = [idx for idx, value in enumerate(min_max_scaled_hardware_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int -> due to scaling
    min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data] = min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data].astype(float)

    min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data] = scaler_min_max.fit_transform(min_max_scaled_hardware_sim_data.iloc[:,col_of_interest_min_max_scaled_hardware_sim_data].values)
    classification_ml_wsal.run_kfold_cross(X=min_max_scaled_hardware_sim_data.loc[:, min_max_scaled_hardware_sim_data.columns != "Labels"].values,
                                           y=min_max_scaled_hardware_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("Cross-Validation Hardware Simulation Data with min-max-scaling -> unique labels: " + str(min_max_scaled_hardware_sim_data['Labels'].unique()))
    print("Cross-Validation Hardware Simulation Data with min-max-scaling -> dataframe shape without duplicate entries: " + str(min_max_scaled_hardware_sim_data.shape))
    print("Cross-Validation Hardware Simulation Data with min-max-scaling -> dataframe columns: " + str(list(min_max_scaled_hardware_sim_data.columns)))
    # software simulation data set standalone evaluation
    min_max_scaled_software_sim_data = software_sim_data.copy()
    data_set_name = "min_max_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_min_max_scaled_software_sim_data = [idx for idx, value in enumerate(min_max_scaled_software_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int
    min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data] = min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data].astype(float)

    min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data] = scaler_min_max.fit_transform(min_max_scaled_software_sim_data.iloc[:,col_of_interest_min_max_scaled_software_sim_data].values)
    
    classification_ml_wsal.run_kfold_cross(X=min_max_scaled_software_sim_data.loc[:, min_max_scaled_software_sim_data.columns != "Labels"].values,
                                           y=min_max_scaled_software_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("Cross-Validation Software Simulation Data with min-max-scaling -> unique labels: " + str(min_max_scaled_software_sim_data['Labels'].unique()))
    print("Cross-Validation Software Simulation Data with min-max-scaling -> dataframe shape without duplicate entries: " + str(min_max_scaled_software_sim_data.shape))
    print("Cross-Validation Software Simulation Data with min-max-scaling -> dataframe columns: " + str(list(min_max_scaled_software_sim_data.columns)))
    ############################### end ml setup for min-max normalized data ###############################

    ############################### start ml setup for z-score normalized data ###############################
    # z-score normalization
    scaler_z_score = StandardScaler()
    # hardware sim standalone evaluation
    z_score_scaled_hardware_sim_data = hardware_sim_data.copy()
    # without label value
    data_set_name = "z_score_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_z_score_scaled_hardware_sim_data = [idx for idx, value in enumerate(z_score_scaled_hardware_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int
    z_score_scaled_hardware_sim_data.iloc[:,col_of_interest_z_score_scaled_hardware_sim_data] = z_score_scaled_hardware_sim_data.iloc[:,col_of_interest_z_score_scaled_hardware_sim_data].astype(float)

    z_score_scaled_hardware_sim_data.iloc[:,col_of_interest_z_score_scaled_hardware_sim_data] = scaler_z_score.fit_transform(z_score_scaled_hardware_sim_data.iloc[:,col_of_interest_z_score_scaled_hardware_sim_data].values)
    classification_ml_wsal.run_kfold_cross(X=z_score_scaled_hardware_sim_data.loc[:, z_score_scaled_hardware_sim_data.columns != "Labels"].values,
                                           y=z_score_scaled_hardware_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("Cross-Validation Hardware Simulation Data with z-score-scaling -> unique labels: " + str(z_score_scaled_hardware_sim_data['Labels'].unique()))
    print("Cross-Validation Hardware Simulation Data with z-score-scaling -> dataframe shape without duplicate entries: " + str(z_score_scaled_hardware_sim_data.shape))
    print("Cross-Validation Hardware Simulation Data with z-score-scaling -> dataframe columns: " + str(list(z_score_scaled_hardware_sim_data.columns)))

    # software simulation data set standalone evaluation
    z_score_scaled_software_sim_data = software_sim_data.copy()
    data_set_name = "z_score_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest

    col_of_interest_z_score_scaled_software_sim_data = [idx for idx, value in enumerate(z_score_scaled_software_sim_data.columns) if(value != "Labels")]

    # scaled data will be in float format instead of int
    z_score_scaled_software_sim_data.iloc[:,col_of_interest_z_score_scaled_software_sim_data] = z_score_scaled_software_sim_data.iloc[:,col_of_interest_z_score_scaled_software_sim_data].astype(float)

    z_score_scaled_software_sim_data.iloc[:,col_of_interest_z_score_scaled_software_sim_data] = scaler_z_score.fit_transform(z_score_scaled_software_sim_data.iloc[:,col_of_interest_z_score_scaled_software_sim_data].values)
    classification_ml_wsal.run_kfold_cross(X=z_score_scaled_software_sim_data.loc[:, z_score_scaled_software_sim_data.columns != "Labels"].values,
                                           y=z_score_scaled_software_sim_data["Labels"].values,
                                           encoding_name=encoding_name,
                                           data_set_name=data_set_name,
                                           path_to_store_results=system_path_to_store_results_with_sub_folder,
                                           cv_mode=cross_validation_mode_cmd)
    
    print("Cross-Validation Software Simulation Data with z-score-scaling -> unique labels: " + str(z_score_scaled_software_sim_data['Labels'].unique()))
    print("Cross-Validation Software Simulation Data with z-score-scaling -> dataframe shape without duplicate entries: " + str(z_score_scaled_software_sim_data.shape))
    print("Cross-Validation Software Simulation Data with z-score-scaling -> dataframe columns: " + str(list(z_score_scaled_software_sim_data.columns)))
    ############################### end ml setup for z-score normalized data ###############################

    ############################### start ml setup cominded hardware / software data ###############################
    # prepare data for combine (hardware sim data & software sim data ml evaluation with scaled data values)
    combined_data_set_min_max_scaled = combined_data_set.copy()
    # label and hardware_or_software cols excluded
    col_of_interest_min_max_scaled = [idx for idx, value in enumerate(combined_data_set_min_max_scaled.columns) if((value != "Labels") and (value != "Hardware_or_Software"))]

    # scaled data will be in float format instead of int
    combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled] = combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled].astype(float)

    combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled] = scaler_min_max.fit_transform(combined_data_set_min_max_scaled.iloc[:,col_of_interest_min_max_scaled].values)

    hardware_sim_combined_min_max_scaled = combined_data_set_min_max_scaled.loc[combined_data_set_min_max_scaled["Hardware_or_Software"] == "Hardware"]
    software_sim_combined_min_max_scaled = combined_data_set_min_max_scaled.loc[combined_data_set_min_max_scaled["Hardware_or_Software"] == "Software"]
    hardware_sim_combined_min_max_scaled.drop("Hardware_or_Software", inplace=True, axis=1)
    software_sim_combined_min_max_scaled.drop("Hardware_or_Software", inplace=True, axis=1)

    data_set_name = "min_max_scaled_hardware_test_data_software_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=software_sim_combined_min_max_scaled.loc[:, software_sim_combined_min_max_scaled.columns != "Labels"].values,
                                          X_test= hardware_sim_combined_min_max_scaled.loc[:, hardware_sim_combined_min_max_scaled.columns != "Labels"].values,
                                          y_train=software_sim_combined_min_max_scaled['Labels'].values,
                                          y_test=hardware_sim_combined_min_max_scaled['Labels'].values,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation min-max-scaled -> train data: software simulation data")
    print("combined evaluation software and hardware simulation min-max-scaled -> test data: hardware simulation data")
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (software simulation data) -> unique labels: " + str(software_sim_combined_min_max_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (hardware simulation data) -> unique labels: " + str(hardware_sim_combined_min_max_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_combined_min_max_scaled.shape))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_combined_min_max_scaled.shape))
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (software simulation data) -> dataframe columns: " + str(list(software_sim_combined_min_max_scaled.columns)))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_combined_min_max_scaled.columns)))
    
    data_set_name = "min_max_scaled_software_test_data_hardware_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=hardware_sim_combined_min_max_scaled.loc[:, hardware_sim_combined_min_max_scaled.columns != "Labels"].values,
                                          X_test=software_sim_combined_min_max_scaled.loc[:, software_sim_combined_min_max_scaled.columns != "Labels"].values,
                                          y_train=hardware_sim_combined_min_max_scaled['Labels'].values,
                                          y_test=software_sim_combined_min_max_scaled['Labels'].values,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation min-max-scaled -> train data: hardware simulation data")
    print("combined evaluation software and hardware simulation min-max-scaled -> test data: software simulation data")
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (hardware simulation data) -> unique labels: " + str(hardware_sim_combined_min_max_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (software simulation data) -> unique labels: " + str(software_sim_combined_min_max_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_combined_min_max_scaled.shape))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_combined_min_max_scaled.shape))
    print("combined evaluation software and hardware simulation min-max-scaled -> train data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_combined_min_max_scaled.columns)))
    print("combined evaluation software and hardware simulation min-max-scaled -> test data (software simulation data) -> dataframe columns: " + str(list(software_sim_combined_min_max_scaled.columns)))

    combined_data_set_z_score_scaled = combined_data_set.copy()
    # label and hardware_or_software cols excluded
    col_of_interest_z_score_scaled = [idx for idx, value in enumerate(combined_data_set_z_score_scaled.columns) if((value != "Labels") and (value != "Hardware_or_Software"))]

    # scaled data will be in float format instead of int
    combined_data_set_z_score_scaled.iloc[:,col_of_interest_z_score_scaled] = combined_data_set_z_score_scaled.iloc[:,col_of_interest_z_score_scaled].astype(float)

    combined_data_set_z_score_scaled.iloc[:,col_of_interest_z_score_scaled] = scaler_z_score.fit_transform(combined_data_set_z_score_scaled.iloc[:,col_of_interest_z_score_scaled].values)

    hardware_sim_combined_z_score_scaled = combined_data_set_z_score_scaled.loc[combined_data_set_z_score_scaled["Hardware_or_Software"] == "Hardware"]
    software_sim_combined_z_score_scaled = combined_data_set_z_score_scaled.loc[combined_data_set_z_score_scaled["Hardware_or_Software"] == "Software"]
    hardware_sim_combined_z_score_scaled.drop("Hardware_or_Software", inplace=True, axis=1)
    software_sim_combined_z_score_scaled.drop("Hardware_or_Software", inplace=True, axis=1)

    data_set_name = "z_score_scaled_hardware_test_data_software_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=software_sim_combined_z_score_scaled.loc[:, software_sim_combined_z_score_scaled.columns != "Labels"].values,
                                          X_test=hardware_sim_combined_z_score_scaled.loc[:, hardware_sim_combined_z_score_scaled.columns != "Labels"].values,
                                          y_train=software_sim_combined_z_score_scaled['Labels'].values,
                                          y_test=hardware_sim_combined_z_score_scaled['Labels'].values,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation z-score-scaled -> train data: software simulation data")
    print("combined evaluation software and hardware simulation z-score-scaled -> test data: hardware simulation data")
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (software simulation data) -> unique labels: " + str(software_sim_combined_z_score_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (hardware simulation data) -> unique labels: " + str(hardware_sim_combined_z_score_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_combined_z_score_scaled.shape))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_combined_z_score_scaled.shape))
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (software simulation data) -> dataframe columns: " + str(list(software_sim_combined_z_score_scaled.columns)))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_combined_z_score_scaled.columns)))
    
    data_set_name = "z_score_scaled_software_test_data_hardware_train_data_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=hardware_sim_combined_z_score_scaled.loc[:, hardware_sim_combined_z_score_scaled.columns != "Labels"].values,
                                          X_test=software_sim_combined_z_score_scaled.loc[:, software_sim_combined_z_score_scaled.columns != "Labels"].values,
                                          y_train=hardware_sim_combined_z_score_scaled['Labels'].values,
                                          y_test=software_sim_combined_z_score_scaled['Labels'].values,
                                          encoding_name=encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    print("combined evaluation software and hardware simulation z-score-scaled -> train data: hardware simulation data")
    print("combined evaluation software and hardware simulation z-score-scaled -> test data: software simulation data")
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (hardware simulation data) -> unique labels: " + str(hardware_sim_combined_z_score_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (software simulation data) -> unique labels: " + str(software_sim_combined_z_score_scaled['Labels'].unique()))
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (hardware simulation data) -> dataframe shape without duplicate entries: " + str(hardware_sim_combined_z_score_scaled.shape))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (software simulation data) -> dataframe shape without duplicate entries: " + str(software_sim_combined_z_score_scaled.shape))
    print("combined evaluation software and hardware simulation z-score-scaled -> train data (hardware simulation data) -> dataframe columns: " + str(list(hardware_sim_combined_z_score_scaled.columns)))
    print("combined evaluation software and hardware simulation z-score-scaled -> test data (software simulation data) -> dataframe columns: " + str(list(software_sim_combined_z_score_scaled.columns)))
    ############################### end ml setup cominded hardware / software data ###############################

    ############################### start train test splits for hardware and simulation data sets (scaled & unscaled) ###############################
    # software simulation data not scaled
    X_train_software_sim_not_scaled, X_test_software_sim_not_scaled, y_train_software_sim_not_scaled, y_test_software_sim_not_scaled = train_test_split(
        software_sim_data.loc[:, software_sim_data.columns != "Labels"].values, software_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_software_sim_not_scaled,
                                          X_test=X_test_software_sim_not_scaled,
                                          y_train=y_train_software_sim_not_scaled,
                                          y_test=y_test_software_sim_not_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    # hardware simulation data not scaled
    X_train_hardware_sim_not_scaled, X_test_hardware_sim_not_scaled, y_train_hardware_sim_not_scaled, y_test_hardware_sim_not_scaled = train_test_split(
        hardware_sim_data.loc[:, hardware_sim_data.columns != "Labels"].values, hardware_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_hardware_sim_not_scaled,
                                          X_test=X_test_hardware_sim_not_scaled,
                                          y_train=y_train_hardware_sim_not_scaled,
                                          y_test=y_test_hardware_sim_not_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    # software simulation data min-max-scaled
    X_train_software_sim_min_max_scaled, X_test_software_sim_min_max_scaled, y_train_software_sim_min_max_scaled, y_test_software_sim_min_max_scaled = train_test_split(
        min_max_scaled_software_sim_data.loc[:, min_max_scaled_software_sim_data.columns != "Labels"].values, min_max_scaled_software_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "min_max_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_software_sim_min_max_scaled,
                                          X_test=X_test_software_sim_min_max_scaled,
                                          y_train=y_train_software_sim_min_max_scaled,
                                          y_test=y_test_software_sim_min_max_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    # hardware simulation data min-max-scaled
    X_train_hardware_sim_min_max_scaled, X_test_hardware_sim_min_max_scaled, y_train_hardware_sim_min_max_scaled, y_test_hardware_sim_min_max_scaled = train_test_split(
        min_max_scaled_hardware_sim_data.loc[:, min_max_scaled_hardware_sim_data.columns != "Labels"].values, min_max_scaled_hardware_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "min_max_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_hardware_sim_min_max_scaled,
                                          X_test=X_test_hardware_sim_min_max_scaled,
                                          y_train=y_train_hardware_sim_min_max_scaled,
                                          y_test=y_test_hardware_sim_min_max_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    # software simulation data z-score
    X_train_software_sim_z_score_scaled, X_test_software_sim_z_score_scaled, y_train_software_sim_z_score_scaled, y_test_software_sim_z_score_scaled = train_test_split(
        z_score_scaled_software_sim_data.loc[:, z_score_scaled_software_sim_data.columns != "Labels"].values, z_score_scaled_software_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "z_score_scaled_software_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_software_sim_z_score_scaled,
                                          X_test=X_test_software_sim_z_score_scaled,
                                          y_train=y_train_software_sim_z_score_scaled,
                                          y_test=y_test_software_sim_z_score_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    # hardware simulation data z-score
    X_train_hardware_sim_z_score_scaled, X_test_hardware_sim_z_score_scaled, y_train_hardware_sim_z_score_scaled, y_test_hardware_sim_z_score_scaled = train_test_split(
        z_score_scaled_hardware_sim_data.loc[:, z_score_scaled_hardware_sim_data.columns != "Labels"].values, z_score_scaled_hardware_sim_data["Labels"].values, test_size=0.5, random_state=42
    )
    data_set_name = "z_score_scaled_hardware_sim_23_all_simulation_runs_" + sim_user_of_interest
    classification_ml_wsal.evaluate_model(X_train=X_train_hardware_sim_z_score_scaled,
                                          X_test=X_test_hardware_sim_z_score_scaled,
                                          y_train=y_train_hardware_sim_z_score_scaled,
                                          y_test=y_test_hardware_sim_z_score_scaled,
                                          encoding_name= encoding_name,
                                          data_set_name=data_set_name,
                                          path_to_store_results=system_path_to_store_results_with_sub_folder)
    
    ############################### end train test splits for hardware and simulation data sets (scaled & unscaled) ###############################

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
        
        parser.add_argument('system_path_gzip_folder_hardware_sim', type=str, help="system path which includes compressed (gzip) Windows security audit log files for hardware simulation (type:str) (e.g., /home/user/data/hardware/storage_data_mining)")
        parser.add_argument('system_path_gzip_folder_software_sim', type=str, help="system path which includes compressed (gzip) Windows security audit log files for software simulation (type:str) (e.g., /home/user/data/software/storage_data_mining)")
        parser.add_argument('path_to_store_ml_results', type=str, help="system path which includes compressed (gzip) Windows security audit log files (type:str) (e.g., /home/user/ml_results)")
        parser.add_argument('sim_user_of_interest', type=str, help="string with simulation user data to evaluate (type:str) (e.g., SimUser001)")
        parser.add_argument('label_mode', type=str, help="data labeling model (type:str) (choose between: general_label_mode, granular_label_mode)")
        parser.add_argument('time_window_size_event_grouping', type=str, help="size of time windows for event grouping in seconds (type:str) (e.g., s, 2s, 3s)")
        parser.add_argument('cross_validation_mode', type=str, help="define if normal cross-validation or stratified cross-validation will be used to evaluation single hardware or software data set (type:str) (values: normal_cv_mode, stratified_cv_mode)")
        parser.add_argument('iteration_timestamp_hardware_simulation', type=str, help="")
        parser.add_argument('iteration_timestamp_software_simulation', type=str, help="")
        parser.add_argument('system_path_to_save_encoded_data', type=str, help="save  values: system path, to store encoded data | skip, to not save encoded data")
        args = parser.parse_args()
        system_path_gzip_folder_hardware_sim_cmd = args.system_path_gzip_folder_hardware_sim
        system_path_gzip_folder_software_sim_cmd = args.system_path_gzip_folder_software_sim
        path_to_store_ml_results_cmd = args.path_to_store_ml_results
        sim_user_of_interest_cmd = args.sim_user_of_interest
        label_mode_cmd = args.label_mode
        cross_validation_mode_cmd = args.cross_validation_mode
        time_window_size_event_grouping_cmd = args.time_window_size_event_grouping
        iteration_timestamp_hardware_simulation_cmd = args.iteration_timestamp_hardware_simulation
        iteration_timestamp_software_simulation_cmd = args.iteration_timestamp_software_simulation
        system_path_to_save_encoded_data_cmd = args.system_path_to_save_encoded_data

        return_code = main(system_path_gzip_folder_hardware_sim_cmd, system_path_gzip_folder_software_sim_cmd, path_to_store_ml_results_cmd, sim_user_of_interest_cmd, label_mode_cmd, time_window_size_event_grouping_cmd, cross_validation_mode_cmd, iteration_timestamp_hardware_simulation_cmd, iteration_timestamp_software_simulation_cmd, system_path_to_save_encoded_data_cmd)
        quit(return_code)
    else:
        main()