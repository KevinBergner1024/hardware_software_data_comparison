import pathlib
import pandas as pd
import os
import scipy
import scipy.stats
import argparse
import textwrap
import resource

CMD_MODE_ENABLED = True
NAME = "WASSERSTEIN DISTANCE COMPUTATION ITERATION-WISE"
VERSION = "1.0"

def compute_wasserstein_distance(data_set_one: pd.DataFrame, data_set_two: pd.DataFrame, normalization: bool = True):
    """ compute 1-dimensional wasserstein distance for two sub data sets

    Args:
        data_set_one (pd.DataFrame): simulation Windows 10 client user specific data of single iteration recording
        data_set_two (pd.DataFrame): simulation Windows 10 client user specific data of single iteration recording
        normalization (bool): value to decide if value frequency counts should be normalized first before computing Wasserstein distance (based on proportion). Defaults to True.

    Returns:
        float: Wasserstein distance
    """
    value_count_first_data_set = data_set_one.value_counts(normalize=normalization)
    value_count_second_data_set = data_set_two.value_counts(normalize=normalization)

    value_count_first_data_set = pd.DataFrame({'SYSTEM_EventID': value_count_first_data_set.index, "Frequency_Count": value_count_first_data_set.values}).sort_values(by="SYSTEM_EventID")
    value_count_second_data_set = pd.DataFrame({'SYSTEM_EventID': value_count_second_data_set.index, "Frequency_Count": value_count_second_data_set.values}).sort_values(by="SYSTEM_EventID")

    data = pd.merge(value_count_first_data_set, value_count_second_data_set, on="SYSTEM_EventID")
    ws_distance = scipy.stats.wasserstein_distance(data.iloc[:, 1].values, data.iloc[:, 2].values)

    return ws_distance

def limit_memory(maxsize: int): 
    """set limit of RAM to use (works only with Linux)

    Args:
        maxsize (int): max RAM usage in bytes
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

def main(sim_user_of_interest_first_data_set: str, system_path_to_first_data_set: str, sim_user_of_interest_second_data_set: str, system_path_to_second_data_set: str, max_ram_usage_bytes: int, system_path_to_store_results: str):

    limit_memory(max_ram_usage_bytes)
    
    system_path_to_first_data_set = pathlib.Path(system_path_to_first_data_set)
    system_path_to_second_data_set = pathlib.Path(system_path_to_second_data_set)
    system_path_to_store_results = pathlib.Path(system_path_to_store_results)

    # all iterations for hardware and software simulation, each 120 iterations
    first_data_set_file_names = [entry[2] for entry in os.walk(system_path_to_first_data_set)][0]
    second_data_set_file_names = [entry[2] for entry in os.walk(system_path_to_second_data_set)][0]

    # get Windows 10 client user specific 30 iteration files
    first_data_set_sim_user_iterations_file_names = [file for file in first_data_set_file_names if(sim_user_of_interest_first_data_set in file)]
    second_data_set_sim_user_iterations_file_names = [file for file in second_data_set_file_names if(sim_user_of_interest_second_data_set in file)]

    results = []

    for idx_first_data_set, first_data_set_file_name in enumerate(first_data_set_sim_user_iterations_file_names):

        current_iteration_first_data_set_system_path = pathlib.Path.joinpath(system_path_to_first_data_set, first_data_set_file_name)

        for idx_second_data_set, second_data_set_file_name in enumerate(second_data_set_sim_user_iterations_file_names):

            current_iteration_second_data_set_system_path = pathlib.Path.joinpath(system_path_to_second_data_set, second_data_set_file_name)
   
            first_data_set = pd.read_csv(current_iteration_first_data_set_system_path, compression="gzip", usecols=["SYSTEM_EventID"])
            second_data_set = pd.read_csv(current_iteration_second_data_set_system_path, compression="gzip", usecols=["SYSTEM_EventID"])

            wsd_normalized = compute_wasserstein_distance(first_data_set, second_data_set, True)
            wsd_not_normalized = compute_wasserstein_distance(first_data_set, second_data_set, False)
            
            results.append([first_data_set_file_name, second_data_set_file_name, wsd_normalized, wsd_not_normalized])
            
    
    df = pd.DataFrame(results, columns=['First_Data_Set_Name', 'Second_Data_Set_Name', 'Wasserstein_Distance_Normalized', 'Wasserstein_Distance_Not_Normalized'])
    
    df["Wasserstein_Distance_Normalized"] = df["Wasserstein_Distance_Normalized"].astype('float')
    df["Wasserstein_Distance_Not_Normalized"] = df["Wasserstein_Distance_Not_Normalized"].astype('float')

    first_part_result_file_name = first_data_set_file_names[0].split('sim23')[0]
    second_part_result_file_name= second_data_set_file_names[0].split('sim23')[0]

    df.to_csv(pathlib.Path.joinpath(system_path_to_store_results, first_part_result_file_name + sim_user_of_interest_first_data_set + "_" + second_part_result_file_name + sim_user_of_interest_second_data_set + ".csv"), index=False)

    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
        This script is used to compare Wassterstein Distances between two
        Windows 10 simulation user clients iteration-wise. 
        ---------------------------------------------------------------
        Name: %s
        Version: %s
        ---------------------------------------------------------------
        Usage:
        ''')%(NAME, VERSION)))

        parser.add_argument('sim_user_of_interest_first_data_set', type = str, help = "first Windows 10 simulation client of interest (e.g., SimUser001)")
        parser.add_argument('system_path_to_first_data_set', type = str, help = "system path containing Windows 10 security audit logs in GZIP compressed CSV format")
        parser.add_argument('sim_user_of_interest_second_data_set', type = str, help = "second Windows 10 simulation client of interest (e.g., SimUser004)")
        parser.add_argument('system_path_to_second_data_set', type = str, help = "system path containing Windows 10 security audit logs in GZIP compressed CSV format")
        parser.add_argument('max_ram_usage_bytes', type = int, help = "define max ram usage of this script in bytes")
        parser.add_argument('system_path_to_store_results', type = str, help = "system path used to store Wasserstein distance computation results (e.g., /home/results/wasserstein_distances/)")

        args = parser.parse_args()
        sim_user_of_interest_first_data_set_cmd = args.sim_user_of_interest_first_data_set
        system_path_to_first_data_set_cmd = args.system_path_to_first_data_set
        system_path_to_second_data_set_cmd = args.system_path_to_second_data_set
        sim_user_of_interest_second_data_set_cmd = args.sim_user_of_interest_second_data_set
        max_ram_usage_bytes_cmd = args.max_ram_usage_bytes
        system_path_to_store_results_cmd = args.system_path_to_store_results

        return_code = main(sim_user_of_interest_first_data_set = sim_user_of_interest_first_data_set_cmd, system_path_to_first_data_set = system_path_to_first_data_set_cmd, sim_user_of_interest_second_data_set = sim_user_of_interest_second_data_set_cmd, system_path_to_second_data_set = system_path_to_second_data_set_cmd, max_ram_usage_bytes = max_ram_usage_bytes_cmd, system_path_to_store_results = system_path_to_store_results_cmd)
        quit(return_code)
    else:
        main(None, None, None, None, None)