import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns

# executed on Windows 11 system

CMD_MODE_ENABLED = False
NAME = "Host Data Error Log Plotting Based on General Behavior Types"
VERSION = 1.1

def split_error_logs_by_hardware_and_software_error_records(all_error_logs:list):
    """split complete host data error logs by software and hardware simulation type

    Args:
        all_error_logs (list): all host data error logs combined for software and hardware simulation

    Returns:
        list: nested list with first list of hardware simulation error logs and second list for software simulation error logs
    """

    hardware_error_logs = []
    software_error_logs = []

    for idx, entry in enumerate(all_error_logs):
        if("rerun" in entry):
            software_error_logs.append(entry)
        elif("Hardware Sim 23 Run" in entry):
            hardware_error_logs.append(entry)

    return [hardware_error_logs, software_error_logs]
    
def generalize_behavior_types_in_error_log_data(simulation_error_logs:list, simulation_type:str):
    """generalize specific sub behavior types to general behavior types, if included in error logs: copy, peertube, programming, chatting, mailing, mutillidae, encrypt

    Args:
        simulation_error_logs (list): host data error logs
        simulation_type (str): type of simulation for error logs (hardware or software simulation type)

    Returns:
        pd.DataFrame: general user behavior types in structured error log format based on dataframe
    """
    counted_behavior_patterns_by_sim_user = []

    # get detailed behavior type description and type of simulation (hardware or software)
    for idx, ele in enumerate(simulation_error_logs):
        if("SimUser001" in ele):
            counted_behavior_patterns_by_sim_user.append(["SimUser001", ele.split("|")[1], simulation_type])
        elif("SimUser002" in ele):
            counted_behavior_patterns_by_sim_user.append(["SimUser002", ele.split("|")[1], simulation_type])
        elif("SimUser003" in ele):
            counted_behavior_patterns_by_sim_user.append(["SimUser003", ele.split("|")[1], simulation_type])
        elif("SimUser004" in ele):
            counted_behavior_patterns_by_sim_user.append(["SimUser004", ele.split("|")[1], simulation_type])

    # get general behavior type description tag
    for idx, ele in enumerate(counted_behavior_patterns_by_sim_user):
        #counted_behavior_patterns_by_sim_user[idx][1] = ele[1].split("_")[0] - new plot 03.02.2025
        counted_behavior_patterns_by_sim_user[idx][1] = ele[1].split("_")[0] + "_" + ele[1].split("_")[1]

    df_counted_behavior_patterns_by_sim_user = pd.DataFrame(counted_behavior_patterns_by_sim_user, columns=["Simulation User", "Behavior Type", "Simulation Type"])

    return df_counted_behavior_patterns_by_sim_user

def plot_data(data:pd.DataFrame):
    """plot host error log data for final visualization

    Args:
        data (pd.DataFrame): host error log data to visualize
    """
    
    sim_user_list = ["SimUser001", "SimUser002", "SimUser003", "SimUser004"]

    sns.set_style("whitegrid")
    fig, axes = plt.subplots(1, 4, figsize=(15, 5), sharey=True)
    fig.suptitle('Host Data Qualitiy Checks - Number of Error Log Entries')

    for idx, user in enumerate(sim_user_list):
        sim_user_specific_df = data[data["Simulation User"] == user]
        sns.barplot(ax=axes[idx], data=sim_user_specific_df, x="Behavior Type", y="Count Error Log Entries", hue="Simulation Type")
        
        axes[idx].bar_label(axes[idx].containers[0], fontsize=10)
        axes[idx].bar_label(axes[idx].containers[1], fontsize=10)
        axes[idx].set_title(user)
        axes[idx].tick_params(labelrotation=90)
    plt.show()


def main():
    # read error logs from hardware and software simulation combined in one file
    error_logs_data = pathlib.Path(r"C:\Users\kev8693m\database\Coding\gitlab_repos\machine_learning_repository\host_data\cidds_sim_bsi_paper_data_set\quality_evaluation\all_quality_check_errors.log").read_text()
    error_logs_data = error_logs_data.split("\n/home")
    # split initially to tag "Hardware" or "Software" simulation
    data_splitted_hardware_software = split_error_logs_by_hardware_and_software_error_records(error_logs_data)
    
    hardware_simulation_error_logs = generalize_behavior_types_in_error_log_data(data_splitted_hardware_software[0], "Hardware")
    software_simulation_error_logs = generalize_behavior_types_in_error_log_data(data_splitted_hardware_software[1], "Software")

    hardware_and_software_error_logs_concatenated = pd.concat([hardware_simulation_error_logs, software_simulation_error_logs], ignore_index=True)

    hardware_and_software_error_logs_value_counts = hardware_and_software_error_logs_concatenated.value_counts()
    hardware_and_software_error_logs_value_counts_index = hardware_and_software_error_logs_value_counts.index.tolist()
    
    hardware_and_software_error_logs_compromised = []

    for idx, ele in enumerate(hardware_and_software_error_logs_value_counts.tolist()):
        hardware_and_software_error_logs_compromised.append([hardware_and_software_error_logs_value_counts_index[idx][0], hardware_and_software_error_logs_value_counts_index[idx][1], hardware_and_software_error_logs_value_counts_index[idx][2], ele])

    df_hardware_and_software_error_logs_compromised = pd.DataFrame(hardware_and_software_error_logs_compromised, columns=["Simulation User", "Behavior Type", "Simulation Type", "Count Error Log Entries"])
    #with line 60 & 61 disabled -> df_hardware_and_software_error_logs_compromised.to_csv(pathlib.Path(r"C:\Users\kev8693m\database\Coding\gitlab_repos\machine_learning_repository\host_data\cidds_sim_bsi_paper_data_set\quality_evaluation\wal_quality_evaluation_results.csv"))
    plot_data(df_hardware_and_software_error_logs_compromised)

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

        return_code = main()
        quit(return_code)
    else:
        main()