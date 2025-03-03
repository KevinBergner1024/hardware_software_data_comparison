import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns

#https://seaborn.pydata.org/examples/pairgrid_dotplot.html

# execute on Linux system

CMD_MODE_ENABLED = True
NAME = ""
VERSION = 1.0

def load_iteration_time(iteration_times_log_file_path:pathlib.Path):
    # load iteration timestamps
    iteration_timestamps = pathlib.Path(iteration_times_log_file_path).read_text()
    iteration_timestamps = [ele.split(",") for ele in iteration_timestamps.split("\n")]
    iteration_timestamps_df = pd.DataFrame(iteration_timestamps, columns=["File_Name", "Start_Timestamp", "End_Timestamp"])
    
    iteration_timestamps_df["Start_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["Start_Timestamp"]).dt.tz_localize(None) 
    iteration_timestamps_df["End_Timestamp"]  = pd.to_datetime(iteration_timestamps_df["End_Timestamp"]).dt.tz_localize(None) 

    return iteration_timestamps_df

def main(path_to_store_final_plots:pathlib.Path, 
         hardware_data_folder_path:pathlib.Path, 
         software_data_folder_path:pathlib.Path, 
         hardware_iteration_times_file_path:pathlib.Path, 
         software_iteration_times_file_path:pathlib.Path):

    hardware_simulation_and_software_simulation_data_system_folder_path = [["Hardware_Simulation", hardware_data_folder_path, hardware_iteration_times_file_path], ["Software_Simulation", software_data_folder_path, software_iteration_times_file_path]]
    simulation_users = ["SimUser001", "SimUser002", "SimUser003", "SimUser004"]

    # pre-plot configurations
    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(24,8))

    for idx, simulation_data_folder_path in enumerate(hardware_simulation_and_software_simulation_data_system_folder_path):
        iteration_event_count_per_simulation = []
        for sub_idx, simulation_user in enumerate(simulation_users):
            # return structure of os.walk: (current system  path in folder, [included sub folder], [included files])
            # get list with all file names in this folder
            complete_system_path_structure = [entry[2] for entry in os.walk(simulation_data_folder_path[1])][0]
    
            # load compressed data for specific simulation user
            files_simulation_user_data_iterations = sorted([entry for entry in complete_system_path_structure if (simulation_user in entry)])
            # 
            for sub_sub_idx, file_name in enumerate(files_simulation_user_data_iterations):
                data = pd.read_csv(pathlib.Path.joinpath(simulation_data_folder_path[1], file_name), compression="gzip", usecols=["SYSTEM_TimeCreated", "Labels"])
                data["SYSTEM_TimeCreated"] = pd.to_datetime(data["SYSTEM_TimeCreated"]).astype('datetime64[s]')
                # print information about current iteration beeing processed 
                print("current file being processed: " + file_name)
                print(data.info())
                print(data.head())
                print(data.shape)

                # START:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files
                #iteration_timestamps_df = load_iteration_time(simulation_data_folder_path[2])
                #start = iteration_timestamps_df.loc[iteration_timestamps_df["File_Name"] == file_name]['Start_Timestamp'].values[0] 
                #end = iteration_timestamps_df.loc[iteration_timestamps_df["File_Name"] == file_name]['End_Timestamp'].values[0]
                #data = data.loc[(data["SYSTEM_TimeCreated"] >= start) & (data["SYSTEM_TimeCreated"] <= end)]
                # END:temporary iteration time cut of pre-converted windows security audit logs -> should be removed after re-created preparsed csv files

                data.sort_values(by='SYSTEM_TimeCreated', inplace = True)
                
                if(idx == 0):
                    iteration_event_count_per_simulation.append(["Hardware Simulation", data.shape[0]])
                elif(idx == 1):
                    iteration_event_count_per_simulation.append(["Software Simulation", data.shape[0]])

        iteration_event_count_per_simulation_df = pd.DataFrame(iteration_event_count_per_simulation, columns=["Simulation_Environment_Type", "Event_Count_Iteration"])
        sns.boxplot(data=iteration_event_count_per_simulation_df, x="Event_Count_Iteration", y = "Simulation_Environment_Type")

    fig.suptitle(' Number Windows Events Per Iteration ', fontsize= 20)
    plt.legend(loc='upper left')
    plt.show()
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
        args = parser.parse_args()
        path_to_store_final_plots_cmd = args.file_path_to_store_final_plots
        hardware_data_folder_path_cmd = args.hardware_data_folder_path
        software_data_folder_path_cmd = args.software_data_folder_path
        hardware_iteration_times_file_path_cmd = args.hardware_iteration_times_file_path
        software_iteration_times_file_path_cmd = args.software_iteration_times_file_path
        return_code = main(pathlib.Path(path_to_store_final_plots_cmd), pathlib.Path(hardware_data_folder_path_cmd), pathlib.Path(software_data_folder_path_cmd), pathlib.Path(hardware_iteration_times_file_path_cmd), pathlib.Path(software_iteration_times_file_path_cmd))
        quit(return_code)
    else:
        main()