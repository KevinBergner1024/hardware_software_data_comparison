import argparse
import textwrap
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import os

import pathlib

NAME = 'Plot Simulation Data Script'
VERSION = '1.0'
CMD_MODE_ENABLED = False

def plotting_add_labels(x,y):
    # source: https://www.geeksforgeeks.org/adding-value-labels-on-a-matplotlib-bar-chart/
    for i in range(len(x)):
        plt.text(i, y[i], y[i], ha = 'center')

def plot_histogram_windows_audit_logs_eventIDs(audit_log_dataframe:pd.DataFrame, event_column_name:pd.Series, x_axis_description:str, y_axis_description:str, title_description:str):
    # method wil be more detailed documented after testing phase
    event_ids = audit_log_dataframe[event_column_name]
    value_counts_event_ids = event_ids.value_counts().to_dict()
    eventIDs = list(value_counts_event_ids.keys())
    count_eventIDs = list(value_counts_event_ids.values())
    plt.bar(eventIDs, count_eventIDs)
    plt.hist(event_ids, bins=50)
    plotting_add_labels(eventIDs, count_eventIDs)
    plt.xlabel(x_axis_description)
    plt.ylabel(y_axis_description)
    plt.title(title_description)
    plt.show()

def general_quality_plot(audit_log_dataframe:pd.DataFrame, x_axis_description:str, y_axis_description:str, title_description:str):
    # method will be more detailed documented after testing phase
    df_copy = audit_log_dataframe.copy()
    start_timestamp = audit_log_dataframe.iloc[0]['SYSTEM_TimeCreated']
    end_timestamp = audit_log_dataframe.iloc[-1]['SYSTEM_TimeCreated']
    stepsize = pd.Timedelta(seconds=3)
    end_of_dataframe_not_reached = True
    count_rows_list = []
    timestamps_list = []

    while(end_of_dataframe_not_reached):
        count_rows_list.append(df_copy.loc[(df_copy['SYSTEM_TimeCreated'] >= start_timestamp) & (df_copy['SYSTEM_TimeCreated'] < (start_timestamp + stepsize))].shape[0])
        timestamps_list.append(start_timestamp)
        start_timestamp = start_timestamp + stepsize
        if(start_timestamp >= end_timestamp):
            end_of_dataframe_not_reached = False

    plt.plot(timestamps_list, count_rows_list)
    plt.xlabel(x_axis_description)
    plt.ylabel(y_axis_description)
    plt.title(title_description)
    plt.show()

    return 0

def hist_plot(audit_log_dataframe:pd.DataFrame):

    sns.set_theme(style="darkgrid")
    sns.set_style("white")
    ax = sns.displot(
        audit_log_dataframe, x="SYSTEM_EventID", col="Labels",
        binwidth=3, height=3, facet_kws=dict(margin_titles=True),
    )

    ax.set_xticklabels(rotation=40, ha="right")
    plt.show()
    return 0

def hist_plot_new(audit_log_dataframe:pd.DataFrame):
    #sns.set_theme(font_scale=1.5, style="white")
    ax = sns.displot(audit_log_dataframe, x="SYSTEM_EventID", col="group_label", height=3)
    ax.set_xticklabels(rotation=40, ha="right")
    plt.tight_layout()
    #plt.show()
    plt.savefig("hardware_sim.png")
    return 0

def plot_train_test_split_machine_learning_results_combined(folder_path_with_host_data_ml_results:pathlib.Path, system_path_to_store_plot:pathlib.Path, simuser:str, title:str, mode:str="non_scaled_data"):

    complete_system_path_structure = [entry[2] for entry in os.walk(folder_path_with_host_data_ml_results)][0]
    files_of_interest = []
    for file in complete_system_path_structure:
        if(mode == "non_scaled_data"):
            if(("hardware_test_data_software_train_data" in str(file)) or ("software_test_data_hardware_train_data" in str(file))) and (not "z_score" in str(file)) and (not "min_max" in str(file) and (not "classification_report" in str(file))):
                files_of_interest.append(file)
                print(files_of_interest)
        elif(mode == "z-score"):
            if(("hardware_test_data_software_train_data" in str(file)) or ("software_test_data_hardware_train_data" in str(file))) and ("z_score" in str(file) and (not "classification_report" in str(file))):
                files_of_interest.append(file)
        elif(mode == "min-max"):
            if(("hardware_test_data_software_train_data" in str(file)) or ("software_test_data_hardware_train_data" in str(file))) and ("min_max" in str(file) and (not "classification_report" in str(file))):
                files_of_interest.append(file)
    
    result_dataframe = pd.DataFrame()
    for result_files in files_of_interest:   
        data = pd.read_csv(pathlib.Path.joinpath(folder_path_with_host_data_ml_results, result_files))
        result_dataframe = pd.concat([result_dataframe, data], ignore_index=True, axis=0)
    print(result_dataframe.info())
    print(result_dataframe.head())
    hardware_test_data_software_train_data_results = result_dataframe[result_dataframe["dataset"].str.contains("hardware_test_data_software_train_data_sim_23_all_simulation_runs")]
    software_test_data_hardware_train_data_results = result_dataframe[result_dataframe["dataset"].str.contains("software_test_data_hardware_train_data_sim_23_all_simulation_runs")]
    print(hardware_test_data_software_train_data_results.info())
    print(software_test_data_hardware_train_data_results.info())
    print(hardware_test_data_software_train_data_results.head())
    print(software_test_data_hardware_train_data_results.head())

    fig, axes = plt.subplots(4,2, figsize=(20,18)) 
    fig.suptitle(title, fontsize=20, weight="bold")

    sns.barplot(ax=axes[0,0], x=hardware_test_data_software_train_data_results["model"], y=hardware_test_data_software_train_data_results["evaluate_model_acc"], color="darkgrey")
    sns.barplot(ax=axes[0,1], x=software_test_data_hardware_train_data_results["model"], y=software_test_data_hardware_train_data_results["evaluate_model_acc"], color="darkgrey")

    sns.barplot(ax=axes[1,0], x=hardware_test_data_software_train_data_results["model"], y=hardware_test_data_software_train_data_results["evaluate_model_precision-weighted"], color="darkgrey")
    sns.barplot(ax=axes[1,1], x=software_test_data_hardware_train_data_results["model"], y=software_test_data_hardware_train_data_results["evaluate_model_precision-weighted"], color="darkgrey")

    sns.barplot(ax=axes[2,0], x=hardware_test_data_software_train_data_results["model"], y=hardware_test_data_software_train_data_results["evaluate_model_recall-weighted"], color="darkgrey")
    sns.barplot(ax=axes[2,1], x=software_test_data_hardware_train_data_results["model"], y=software_test_data_hardware_train_data_results["evaluate_model_recall-weighted"], color="darkgrey")

    sns.barplot(ax=axes[3,0], x=hardware_test_data_software_train_data_results["model"], y=hardware_test_data_software_train_data_results["evaluate_model_f1-weighted"], color="darkgrey")
    sns.barplot(ax=axes[3,1], x=software_test_data_hardware_train_data_results["model"], y=software_test_data_hardware_train_data_results["evaluate_model_f1-weighted"], color="darkgrey")
    
    axes[0, 0].set_title('Hardware Test Data & Software Train Data ' + simuser, fontsize=20)
    axes[0, 1].set_title('Software Test Data & Hardware Train Data ' + simuser, fontsize=20)

    axes[0,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,0].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    axes[0,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,1].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    
    axes[1,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,0].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    axes[1,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,1].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    
    axes[2,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,0].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    axes[2,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,1].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    
    axes[3,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,0].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")
    axes[3,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,1].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")

    plt.tight_layout()
    plt.savefig(pathlib.Path.joinpath(system_path_to_store_plot, title + ".png"))


def plot_train_test_split_machine_learning_results(folder_path_with_host_data_ml_results:pathlib.Path, system_path_to_store_plot:pathlib.Path, simuser:str, train_test_ratio:str, title:str, mode:str="non_scaled_data"):

    complete_system_path_structure = [entry[2] for entry in os.walk(folder_path_with_host_data_ml_results)][0]
    files_of_interest = []
    for file in complete_system_path_structure:
        if(mode == "non_scaled_data"):
            if("train_test_split" in str(file)) and (not "z_score" in str(file)) and (not "min_max" in str(file) and (not "train_data" in str(file)) and (not "test_data" in str(file)) and (not "classification_report" in str(file))):
                files_of_interest.append(file)
        elif(mode == "z-score"):
            if("train_test_split" in str(file)) and ("z_score" in str(file) and (not "train_data" in str(file)) and (not "test_data" in str(file)) and (not "classification_report" in str(file))):
                files_of_interest.append(file)
        elif(mode == "min-max"):
            if("train_test_split" in str(file)) and ("min_max" in str(file) and (not "train_data" in str(file)) and (not "test_data" in str(file)) and (not "classification_report" in str(file))):
                files_of_interest.append(file)

    result_dataframe = pd.DataFrame()
    for result_files in files_of_interest:   
        data = pd.read_csv(pathlib.Path.joinpath(folder_path_with_host_data_ml_results, result_files))
        result_dataframe = pd.concat([result_dataframe, data], ignore_index=True, axis=0)
    print(result_dataframe.info())
    print(result_dataframe.head())
    hardware_results = result_dataframe[result_dataframe["dataset"].str.contains("hardware_sim_23_all_simulation_runs")]
    software_results = result_dataframe[result_dataframe["dataset"].str.contains("software_sim_23_all_simulation_runs")]
    print(hardware_results.info())
    print(software_results.info())
    print(hardware_results.head())
    print(software_results.head())

    fig, axes = plt.subplots(4,2, figsize=(20,18)) 
    fig.suptitle(title, fontsize=20, weight="bold")

    sns.barplot(ax=axes[0,0], x=hardware_results["model"], y=hardware_results["evaluate_model_acc"], color="darkgrey")
    sns.barplot(ax=axes[0,1], x=software_results["model"], y=software_results["evaluate_model_acc"], color="darkgrey")

    sns.barplot(ax=axes[1,0], x=hardware_results["model"], y=hardware_results["evaluate_model_precision-weighted"], color="darkgrey")
    sns.barplot(ax=axes[1,1], x=software_results["model"], y=software_results["evaluate_model_precision-weighted"], color="darkgrey")

    sns.barplot(ax=axes[2,0], x=hardware_results["model"], y=hardware_results["evaluate_model_recall-weighted"], color="darkgrey")
    sns.barplot(ax=axes[2,1], x=software_results["model"], y=software_results["evaluate_model_recall-weighted"], color="darkgrey")

    sns.barplot(ax=axes[3,0], x=hardware_results["model"], y=hardware_results["evaluate_model_f1-weighted"], color="darkgrey")
    sns.barplot(ax=axes[3,1], x=software_results["model"], y=software_results["evaluate_model_f1-weighted"], color="darkgrey")
    
    axes[0, 0].set_title('Hardware Simulation ' + simuser + " " + train_test_ratio, fontsize=20)
    axes[0, 1].set_title('Software Simulation ' + simuser + " " + train_test_ratio, fontsize=20)   

    axes[0,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,0].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    axes[0,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,1].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    
    axes[1,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,0].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    axes[1,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,1].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    
    axes[2,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,0].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    axes[2,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,1].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    
    axes[3,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,0].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")
    axes[3,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,1].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")

    plt.tight_layout()
    plt.savefig(pathlib.Path.joinpath(system_path_to_store_plot, title + ".png"))
        


def plot_cross_validation_machine_learning_results(folder_path_with_host_data_ml_results:pathlib.Path, system_path_to_store_plot:pathlib.Path, title:str, simuser:str, mode:str="non_scaled_data"):

    complete_system_path_structure = [entry[2] for entry in os.walk(folder_path_with_host_data_ml_results)][0]
    files_of_interest = []
    for file in complete_system_path_structure:
        print(file)
        if(mode == "non_scaled_data"):
            if("normal_cv_mode" in str(file)) and (not "z_score" in str(file)) and (not "min_max" in str(file)):
                files_of_interest.append(file)
        elif(mode == "z-score"):
            if("normal_cv_mode" in str(file)) and ("z_score" in str(file)):
                files_of_interest.append(file)
        elif(mode == "min-max"):
            if("normal_cv_mode" in str(file)) and ("min_max" in str(file)):
                files_of_interest.append(file)

    result_dataframe = pd.DataFrame()
    for result_files in files_of_interest:   
        data = pd.read_csv(pathlib.Path.joinpath(folder_path_with_host_data_ml_results, result_files))
        result_dataframe = pd.concat([result_dataframe, data], ignore_index=True, axis=0)

    hardware_results = result_dataframe[result_dataframe["dataset"].str.contains("hardware_sim_23_all_simulation_runs")]
    software_results = result_dataframe[result_dataframe["dataset"].str.contains("software_sim_23_all_simulation_runs")]
 
    fig, axes = plt.subplots(6,2, figsize=(26,18)) 
    fig.suptitle(title, fontsize=20, weight="bold")

    axes[0, 0].set_title('Hardware Simulation ' + simuser, fontsize=20)
    axes[0, 1].set_title('Software Simulation ' + simuser, fontsize=20)
    
    sns.boxplot(ax=axes[0,0], x=hardware_results["model"], y=hardware_results["test_Acc"], color="lightgrey")
    sns.boxplot(ax=axes[0,1], x=software_results["model"], y=software_results["test_Acc"], color="lightgrey")

    sns.boxplot(ax=axes[1,0], x=hardware_results["model"], y=hardware_results["test_Prec-weighted"], color="lightgrey")
    sns.boxplot(ax=axes[1,1], x=software_results["model"], y=software_results["test_Prec-weighted"], color="lightgrey")

    sns.boxplot(ax=axes[2,0], x=hardware_results["model"], y=hardware_results["test_Rec-weighted"], color="lightgrey")
    sns.boxplot(ax=axes[2,1], x=software_results["model"], y=software_results["test_Rec-weighted"], color="lightgrey")

    sns.boxplot(ax=axes[3,0], x=hardware_results["model"], y=hardware_results["test_F1-weighted"], color="lightgrey")
    sns.boxplot(ax=axes[3,1], x=software_results["model"], y=software_results["test_F1-weighted"], color="lightgrey")

    sns.barplot(ax=axes[4,0], x=hardware_results["model"], y=hardware_results["fit_time"], color="darkgrey")
    sns.barplot(ax=axes[4,1], x=software_results["model"], y=software_results["fit_time"], color="darkgrey")

    sns.barplot(ax=axes[5,0], x=hardware_results["model"], y=hardware_results["score_time"], color="darkgrey")
    sns.barplot(ax=axes[5,1], x=software_results["model"], y=software_results["score_time"], color="darkgrey")

    axes[0,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,0].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    axes[0,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[0,1].set(xlabel="Machine Learning Model", ylabel="Test Accuracy")
    
    axes[1,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,0].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    axes[1,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[1,1].set(xlabel="Machine Learning Model", ylabel="Test Precision (Weighted)")
    
    axes[2,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,0].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    axes[2,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[2,1].set(xlabel="Machine Learning Model", ylabel="Test Recall (Weighted)")
    
    axes[3,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,0].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")
    axes[3,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[3,1].set(xlabel="Machine Learning Model", ylabel="Test F-1 (Weighted)")

    axes[4,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[4,0].set(xlabel="Machine Learning Model", ylabel="Fit Time (Seconds)")
    axes[4,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[4,1].set(xlabel="Machine Learning Model", ylabel="Fit Time (Seconds)")

    axes[5,0].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[5,0].set(xlabel="Machine Learning Model", ylabel="Score Time (Seconds)")
    axes[5,1].set_xticklabels(axes[0,0].get_xticklabels(), rotation=30, ha='right')
    axes[5,1].set(xlabel="Machine Learning Model", ylabel="Score Time (Seconds)")

    plt.tight_layout()
    plt.savefig(pathlib.Path.joinpath(system_path_to_store_plot, title + ".png"))


def main():
    # load ml-pipeline results system path structure
    folder_path_with_host_data_ml_results = pathlib.Path(r"C:\Users\kev8693m\database\research_projects\data_set_hard_software_sim_comparison\ml_results_windows_security_logs\ml_results_V_2\results\general_labeling\results_1_s_time_windows\SimUser001")
    plot_cross_validation_machine_learning_results(folder_path_with_host_data_ml_results=folder_path_with_host_data_ml_results, system_path_to_store_plot=pathlib.Path(r"C:\Users\kev8693m\Desktop\test"), simuser="SimUser001", title="5-Cross-Validation-Seperated-Hardware-Software-Data-Non-Scaled")
    plot_train_test_split_machine_learning_results(folder_path_with_host_data_ml_results=folder_path_with_host_data_ml_results, system_path_to_store_plot=pathlib.Path(r"C:\Users\kev8693m\Desktop\test"), simuser="SimUser001", train_test_ratio="60% Train & 40 % Test Split", title="Train-Test-Seperated-Hardware-Software-Data-Non-Scaled")
    plot_train_test_split_machine_learning_results_combined(folder_path_with_host_data_ml_results=folder_path_with_host_data_ml_results, system_path_to_store_plot=pathlib.Path(r"C:\Users\kev8693m\Desktop\test"), simuser="SimUser001", title="Train-Test-Combined-Hardware-Software-Data-Non-Scaled")
    
    
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
        
        return_code = main()
        quit(return_code)
    else:
        main()