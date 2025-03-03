import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns
import sys
import resource

#https://seaborn.pydata.org/examples/pairgrid_dotplot.html
# executed on Linux system

CMD_MODE_ENABLED = True
NAME = ""
VERSION = 1.1

def limit_memory(maxsize): 
    soft, hard = resource.getrlimit(resource.RLIMIT_AS) 
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

def load_iteration_time(iteration_times_log_file_path:pathlib.Path):
    # load iteration timestamps
    iteration_timestamps = pathlib.Path(iteration_times_log_file_path).read_text()
    iteration_timestamps = [ele.split(",") for ele in iteration_timestamps.split("\n")]
    iteration_timestamps_df = pd.DataFrame(iteration_timestamps, columns=["File_Name", "Start_Timestamp", "End_Timestamp"])
    
    iteration_timestamps_df["Start_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["Start_Timestamp"]).dt.tz_localize(None) 
    iteration_timestamps_df["End_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["End_Timestamp"]).dt.tz_localize(None) 

    return iteration_timestamps_df

def apply_general_wsal_labels(dataframe:pd.DataFrame):
    """apply general labeling on loaded windows security audit logs (e.g. [encrypt copy, encrypt decrypt, encrypt copy] -> [encrypt, encrypt, encrypt])

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

def main(path_to_store_final_plots:pathlib.Path, 
         hardware_data_folder_path:pathlib.Path, 
         software_data_folder_path:pathlib.Path, 
         hardware_iteration_times_file_path:pathlib.Path, 
         software_iteration_times_file_path:pathlib.Path,
         system_path_to_store_and_load_preprocessed_data:pathlib.Path,
         preprocessing_enabled:str,
         plotting_enabled:str,
         ram_mem_max_usage_in_bytes:int):

    limit_memory(ram_mem_max_usage_in_bytes)
    hardware_simulation_and_software_simulation_data_system_folder_path = [["Hardware_Simulation", hardware_data_folder_path, hardware_iteration_times_file_path], ["Software_Simulation", software_data_folder_path, software_iteration_times_file_path]]
    simulation_users = ["SimUser001", "SimUser002", "SimUser003", "SimUser004"]

    if(preprocessing_enabled == "enabled"):
        for idx, simulation_data_folder_path in enumerate(hardware_simulation_and_software_simulation_data_system_folder_path):
            for sub_idx, simulation_user in enumerate(simulation_users):
                # return structure of os.walk: (current system  path in folder, [included sub folder], [included files])
                # get list with all file names in this folder
                complete_system_path_structure = [entry[2] for entry in os.walk(simulation_data_folder_path[1])][0]
        
                # load compressed data for specific simulation user
                files_simulation_user_data_iterations = sorted([entry for entry in complete_system_path_structure if (simulation_user in entry)])

                # go through each simulation iteration for specific user
                for sub_sub_idx, file_name in enumerate(files_simulation_user_data_iterations):
                    data = pd.read_csv(pathlib.Path.joinpath(simulation_data_folder_path[1], file_name), compression="gzip", usecols=["SYSTEM_TimeCreated", "Labels"])
                    
                    # print information about current iteration beeing processed 
                    print("current file being processed: " + file_name)
                    print(data.info())
                    print(data.head())
                    print(data.shape)

                    data["SYSTEM_TimeCreated"] = pd.to_datetime(data["SYSTEM_TimeCreated"]).astype('datetime64[s]')

                    # START:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files
                    #iteration_timestamps_df = load_iteration_time(simulation_data_folder_path[2])
                    #start = iteration_timestamps_df.loc[iteration_timestamps_df["File_Name"] == file_name]['Start_Timestamp'].values[0] 
                    #end = iteration_timestamps_df.loc[iteration_timestamps_df["File_Name"] == file_name]['End_Timestamp'].values[0]
                    #data = data.loc[(data["SYSTEM_TimeCreated"] >= start) & (data["SYSTEM_TimeCreated"] <= end)]
                    # END:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files

                    data.sort_values(by='SYSTEM_TimeCreated', inplace = True)

                    data = apply_general_wsal_labels(data)
                    data = data.groupby(['Labels']).size().reset_index(name='Count_Events_Per_General_Label')

                    # check if some general behavior is missing in specific user iteration
                    general_behavior_labels = ["chatting", "copy", "encrypt", "mailing", "mutillidae", "peertube", "programming"]
                    general_behavior_included_in_current_iteration = data.loc[data["Labels"] != "no_label"]["Labels"].unique().tolist()
                    
                    if(len(general_behavior_labels) != len(general_behavior_included_in_current_iteration)):
                        missing_general_behavior = list(set(general_behavior_labels) - set(general_behavior_included_in_current_iteration))
                        for behavior in missing_general_behavior:

                            new_row_df = pd.DataFrame({"Labels" : behavior, "Count_Events_Per_General_Label": 0}, index=[0])
                            data = pd.concat([data, new_row_df], ignore_index=True)

                    data["Simulation_User"] = simulation_user
                    data["Simulation_Type"] = simulation_data_folder_path[0]
                        
                    name_to_store_current_data = file_name.split(".")[0]
                    data.to_csv(pathlib.Path.joinpath(system_path_to_store_and_load_preprocessed_data, name_to_store_current_data+".csv"), index=False)

    if(plotting_enabled == "enabled"):

        # laod files names pre-processed to plot data
        files_to_plot = [entry[2] for entry in os.walk(system_path_to_store_and_load_preprocessed_data)][0]
        
        all_data_df = pd.DataFrame()
        for file in files_to_plot:
            df = pd.read_csv(pathlib.Path.joinpath(system_path_to_store_and_load_preprocessed_data, file), index_col=False, usecols=["Labels", "Count_Events_Per_General_Label", "Simulation_User", "Simulation_Type"])
            frames = [all_data_df, df]
            all_data_df = pd.concat(frames, ignore_index=True, copy=False, axis=0)

        sns.set_theme(style="whitegrid")
        fig, ax = plt.subplots(nrows=2, ncols=4, figsize=(26,14))
        
        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "chatting"], ax=ax[0,0], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[0,0].title.set_text('Chatting')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "copy"], ax=ax[0,1], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[0,1].title.set_text('Copy')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "encrypt"], ax=ax[0,2], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[0,2].title.set_text('Encrypt')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "mailing"], ax=ax[0,3], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[0,3].title.set_text('Mailing')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "mutillidae"], ax=ax[1,0], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[1,0].title.set_text('Mutillidae')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "peertube"], ax=ax[1,1], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[1,1].title.set_text('Peertube')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "programming"], ax=ax[1,2], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[1,2].title.set_text('Programming')

        sns.boxplot(all_data_df.loc[all_data_df["Labels"] == "no_label"], ax=ax[1,3], x="Simulation_Type", y="Count_Events_Per_General_Label")
        ax[1,3].title.set_text('No Label')
        
        fig.suptitle(' Windows Security Event Count Per Iteration Seperated by General Behavior Labels ', y=1.00000001)
        fig.tight_layout(pad=0.4)
        plt.savefig(path_to_store_final_plots)

    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog=NAME,
            description=textwrap.dedent(('''
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage:
        ''')%(NAME, VERSION)))
        parser.add_argument('file_path_to_store_final_plots', type=str, help="")
        parser.add_argument('hardware_data_folder_path', type=str, help="")
        parser.add_argument('software_data_folder_path', type=str, help="")
        parser.add_argument('hardware_iteration_times_file_path', type=str, help="")
        parser.add_argument('software_iteration_times_file_path', type=str, help="")
        parser.add_argument('system_path_to_store_and_load_preprocessed_data', type=str, help='')
        parser.add_argument('preprocessing_enabled', type=str, help="enabled or disabled")
        parser.add_argument('plotting_enabled', type=str, help="enabled or disabled")
        parser.add_argument('ram_mem_max_usage_in_bytes', type=int, help="")
        args = parser.parse_args()
        path_to_store_final_plots_cmd = args.file_path_to_store_final_plots
        hardware_data_folder_path_cmd = args.hardware_data_folder_path
        software_data_folder_path_cmd = args.software_data_folder_path
        hardware_iteration_times_file_path_cmd = args.hardware_iteration_times_file_path
        software_iteration_times_file_path_cmd = args.software_iteration_times_file_path
        system_path_to_store_and_load_preprocessed_data_cmd = args.system_path_to_store_and_load_preprocessed_data
        preprocessing_enabled_cmd = args.preprocessing_enabled
        plotting_enabled_cmd = args.plotting_enabled
        ram_mem_max_usage_in_bytes_cmd = args.ram_mem_max_usage_in_bytes
        return_code = main(pathlib.Path(path_to_store_final_plots_cmd), pathlib.Path(hardware_data_folder_path_cmd), pathlib.Path(software_data_folder_path_cmd), pathlib.Path(hardware_iteration_times_file_path_cmd),
                           pathlib.Path(software_iteration_times_file_path_cmd), pathlib.Path(system_path_to_store_and_load_preprocessed_data_cmd), preprocessing_enabled_cmd, plotting_enabled_cmd, ram_mem_max_usage_in_bytes_cmd)
        quit(return_code)
    else:
        main()