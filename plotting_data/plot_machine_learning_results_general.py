import matplotlib.pyplot as plt
import pandas as pd 
import argparse
import textwrap
import os
import pathlib
import seaborn as sns

# execute on Windows 11 system
CMD_MODE_ENABLED = False
NAME = "plot general result of machine learning evaluation"
VERSION = 1.0

def main():
    system_path_containing_ml_results_to_evaluate = pathlib.Path(r"C:\Users\kev8693m\database\research_projects\data_set_hard_software_sim_comparison\computing results\ml_pipeline_14_02_2025\granular_labeling")
    # load all folder paths that include ml result files
    simuser_time_window_labeling_specifc_result_folder_paths = [entry[0] for entry in os.walk(system_path_containing_ml_results_to_evaluate) if entry[2] != []]
    all_ml_results_df = pd.DataFrame()

    # iterate through each folder path that includes ml result files 
    for result_folder in simuser_time_window_labeling_specifc_result_folder_paths:
        result_files_of_interest = [file for entry in os.walk(result_folder) for file in entry[2] if ("train_test" in file) & ("classification_report" not in file)]
        # load all 
        for file in result_files_of_interest:
            current_file_results_df = pd.read_csv(pathlib.Path.joinpath(pathlib.Path(result_folder), file), index_col=0)
            all_ml_results_df = pd.concat([all_ml_results_df, current_file_results_df], ignore_index=True, copy=False, axis=0)

    software_ds_results = all_ml_results_df.loc[(all_ml_results_df["dataset"] == "software_sim_23_all_simulation_runs_SimUser001") | (all_ml_results_df["dataset"] == "software_sim_23_all_simulation_runs_SimUser002") | (all_ml_results_df["dataset"] == "software_sim_23_all_simulation_runs_SimUser003") | (all_ml_results_df["dataset"] == "software_sim_23_all_simulation_runs_SimUser004")]
    hardware_ds_results = all_ml_results_df.loc[(all_ml_results_df["dataset"] == "hardware_sim_23_all_simulation_runs_SimUser001") | (all_ml_results_df["dataset"] == "hardware_sim_23_all_simulation_runs_SimUser002") | (all_ml_results_df["dataset"] == "hardware_sim_23_all_simulation_runs_SimUser003") | (all_ml_results_df["dataset"] == "hardware_sim_23_all_simulation_runs_SimUser004")]
    software_test_hardware_train_ds_result = all_ml_results_df.loc[(all_ml_results_df["dataset"] == "software_test_data_hardware_train_data_sim_23_all_simulation_runs_SimUser001") | (all_ml_results_df["dataset"] == "software_test_data_hardware_train_data_sim_23_all_simulation_runs_SimUser002") | (all_ml_results_df["dataset"] == "software_test_data_hardware_train_data_sim_23_all_simulation_runs_SimUser003") | (all_ml_results_df["dataset"] == "software_test_data_hardware_train_data_sim_23_all_simulation_runs_SimUser004")]
    hardware_test_software_train_ds_result = all_ml_results_df.loc[(all_ml_results_df["dataset"] == "hardware_test_data_software_train_data_sim_23_all_simulation_runs_SimUser001") | (all_ml_results_df["dataset"] == "hardware_test_data_software_train_data_sim_23_all_simulation_runs_SimUser002") | (all_ml_results_df["dataset"] == "hardware_test_data_software_train_data_sim_23_all_simulation_runs_SimUser003") | (all_ml_results_df["dataset"] == "hardware_test_data_software_train_data_sim_23_all_simulation_runs_SimUser004")]

    ml_results_of_interest = pd.DataFrame()
    ml_results_of_interest = pd.concat([ml_results_of_interest, software_ds_results], ignore_index=True, copy=False, axis=0)
    ml_results_of_interest = pd.concat([ml_results_of_interest, hardware_ds_results], ignore_index=True, copy=False, axis=0)
    ml_results_of_interest = pd.concat([ml_results_of_interest, software_test_hardware_train_ds_result], ignore_index=True, copy=False, axis=0)
    ml_results_of_interest = pd.concat([ml_results_of_interest, hardware_test_software_train_ds_result], ignore_index=True, copy=False, axis=0)
    ml_results_of_interest.reset_index()
    
    ml_results_of_interest.loc[ml_results_of_interest['dataset'].str.contains("software_sim_23_all_simulation_runs"), "dataset"] = "software_sim_23_all_simulation"
    ml_results_of_interest.loc[ml_results_of_interest['dataset'].str.contains("hardware_sim_23_all_simulation_runs"), "dataset"] = "hardware_sim_23_all_simulation"
    ml_results_of_interest.loc[ml_results_of_interest['dataset'].str.contains("software_test_data_hardware_train_data_sim_23_all_simulation_runs"), "dataset"] = "software_test_data_hardware_train_data_sim_23"
    ml_results_of_interest.loc[ml_results_of_interest['dataset'].str.contains("hardware_test_data_software_train_data_sim_23_all_simulation_runs"), "dataset"] = "hardware_test_data_software_train_data_sim_23"

    sns.set_style("whitegrid")
    fig, ax = plt.subplots(ncols=4, figsize=(15, 10), sharex=True, sharey=True)

    sns.boxplot(ml_results_of_interest, x="evaluate_model_acc",hue="encoding", y="dataset", ax=ax[0], width=0.3)
    sns.boxplot(ml_results_of_interest, x="evaluate_model_precision-weighted",hue="encoding", y="dataset", ax=ax[1], width=0.3)
    sns.boxplot(ml_results_of_interest, x="evaluate_model_recall-weighted",hue="encoding", y="dataset", ax=ax[2], width=0.3)
    sns.boxplot(ml_results_of_interest, x="evaluate_model_f1-weighted",hue="encoding", y="dataset", ax=ax[3], width=0.3)

    # remove subplot legends first
    [ax[idx].get_legend().remove() for idx, value in enumerate(range(4))]

    # create one general label for all subplots
    handles, labels = ax[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right', ncol=3, bbox_to_anchor=(0.8, 1), frameon=False)

    plt.tight_layout()
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

        return_code = main()
        quit(return_code)
    else:
        main()