import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns

#https://seaborn.pydata.org/examples/pairgrid_dotplot.html
# executed on Linux system

# python plot_accum_wsal_event_count_per_secs.py /home/kevin/Pictures/plot_accum_wsal_event_count_per_sec.png /home/kevin/mnt/nas/simdata/valid_hardware_sim23/converted_wal/ /home/kevin/mnt/nas/simdata/valid_software_sim23/converted_wal/ /home/kevin/repos/machine_learning_repository/host_data/cidds_sim_bsi_paper_data_set/iteration_timestamps_hardware_simulation.txt /home/kevin/repos/machine_learning_repository/host_data/cidds_sim_bsi_paper_data_set/iteration_timestamps_software_simulation.txt

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
    fig, ax = plt.subplots(2, figsize=(24,12))

    for idx, simulation_data_folder_path in enumerate(hardware_simulation_and_software_simulation_data_system_folder_path):
        # iterate through all runs of hardware or simulation setup for a specific user
        for sub_idx, simulation_user in enumerate(simulation_users):
            all_runs_of_simulation_setup_hardware_or_software = []
            # return structure of os.walk: (current system  path in folder, [included sub folder], [included files])
            # get list with all file names in this folder
            complete_system_path_structure = [entry[2] for entry in os.walk(simulation_data_folder_path[1])][0]
    
            # load compressed iteration data files for specific simulation user
            files_simulation_user_data_iterations = sorted([entry for entry in complete_system_path_structure if (simulation_user in entry)])
            # iterate through each iteration data set
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
                all_runs_of_simulation_setup_hardware_or_software = all_runs_of_simulation_setup_hardware_or_software + data.values.tolist()
            
            all_runs_of_simulation_setup_hardware_or_software_df = pd.DataFrame(all_runs_of_simulation_setup_hardware_or_software, columns=["SYSTEM_TimeCreated", "Labels"])
            all_runs_of_simulation_setup_hardware_or_software_df["SYSTEM_TimeCreated"] = pd.to_datetime(all_runs_of_simulation_setup_hardware_or_software_df["SYSTEM_TimeCreated"]).astype('datetime64[s]')
            all_runs_of_simulation_setup_hardware_or_software_df.sort_values(by='SYSTEM_TimeCreated', inplace = True)

            all_runs_of_simulation_setup_hardware_or_software_df = all_runs_of_simulation_setup_hardware_or_software_df.groupby(['SYSTEM_TimeCreated']).size().reset_index(name='Frequency')
            all_runs_of_simulation_setup_hardware_or_software_df.sort_values(by='SYSTEM_TimeCreated', inplace = True)
            all_runs_of_simulation_setup_hardware_or_software_df["Cummulative_Sum"] = all_runs_of_simulation_setup_hardware_or_software_df["Frequency"].cumsum()

            # based on high level hardware_simulation_and_software_simulation_data_system_folder_path list structure/order
            if(idx == 0):
                sns.lineplot(ax=ax[0], data=all_runs_of_simulation_setup_hardware_or_software_df, x="SYSTEM_TimeCreated",y="Cummulative_Sum", label="Hardware Simulation " + simulation_user)
            else:
                sns.lineplot(ax=ax[1], data=all_runs_of_simulation_setup_hardware_or_software_df, x="SYSTEM_TimeCreated",y="Cummulative_Sum", linestyle="--", label="Software Simulation " + simulation_user)

    fig.suptitle(' Accumulated Windows Security Event Count per Second ', fontsize= 20)
    plt.legend(loc='upper left')
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