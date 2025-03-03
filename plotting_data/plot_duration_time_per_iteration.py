import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns

#https://seaborn.pydata.org/examples/pairgrid_dotplot.html
# executed on Windows 11 system

CMD_MODE_ENABLED = False
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

def main():
    hardware_iteration_timestamps_file_path = pathlib.Path(r"C:\Users\kev8693m\database\Coding\gitlab_repos\machine_learning_repository\host_data\cidds_sim_bsi_paper_data_set\iteration_timestamps_hardware_simulation.txt")
    software_iteration_timestamps_file_path = pathlib.Path(r"C:\Users\kev8693m\database\Coding\gitlab_repos\machine_learning_repository\host_data\cidds_sim_bsi_paper_data_set\iteration_timestamps_software_simulation.txt")
    
    hardware_iteration_data = load_iteration_time(hardware_iteration_timestamps_file_path)
    hardware_iteration_data["Duration_Per_Iteration"] = hardware_iteration_data["End_Timestamp"] - hardware_iteration_data["Start_Timestamp"]
    hardware_iteration_data["Simulation_Type"] = "Hardware Simulation"
    print(hardware_iteration_data)
    print(hardware_iteration_data.info())

    software_iteration_data = load_iteration_time(software_iteration_timestamps_file_path)
    software_iteration_data["Duration_Per_Iteration"] = software_iteration_data["End_Timestamp"] - software_iteration_data["Start_Timestamp"]
    software_iteration_data["Simulation_Type"] = "Software Simulation"
    print(software_iteration_data)
    print(software_iteration_data.info())

    final_dataframe_to_plot = pd.concat([hardware_iteration_data, software_iteration_data], ignore_index=True, axis=0)
    print(final_dataframe_to_plot)
    print(final_dataframe_to_plot.info())

    final_dataframe_to_plot["Duration_Per_Iteration"] = final_dataframe_to_plot["Duration_Per_Iteration"].dt.total_seconds()
    print(final_dataframe_to_plot)
    print(final_dataframe_to_plot.info())
    
    # add simulation user tag to dataframe entry
    final_dataframe_to_plot["Simulation_User"] = [test for value in final_dataframe_to_plot["File_Name"] for test in value.split("_") if "SimUser" in test]
    print(final_dataframe_to_plot.head())


    sns.set_theme(style="whitegrid")
    fig, (ax1, ax2, ax3, ax4) = plt.subplots(ncols=4, figsize=(12,6), sharey="row")

    
    simulation_users = ["SimUser001", "SimUser002", "SimUser003", "SimUser004"]
    axes_dict = {
        0 : ax1,
        1 : ax2,
        2 : ax3,
        3 : ax4
    }

    for idx, user in enumerate(simulation_users):

        sns.violinplot(ax=axes_dict[idx], data=final_dataframe_to_plot.loc[final_dataframe_to_plot["Simulation_User"] == user], x="Simulation_User", y="Duration_Per_Iteration", hue="Simulation_Type")
        axes_dict[idx].set_xlabel("Simulation User")
        axes_dict[idx].set_ylabel("Duration Time Per Iteration in Seconds")
    
    fig.suptitle(' Duration Time Per Iteration in Seconds Overview ', fontsize= 20)
    plt.show()

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