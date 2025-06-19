import pandas as pd
import pathlib
import os
import matplotlib.pylab as plt
import seaborn as sns
import re


def remove_itr_idx(iteration_client_specific):
    # just for hardware data
    if re.search('hw', iteration_client_specific):
 
        pos_start = re.search('\[.*', iteration_client_specific).start()
        pos_end = re.search('\].*', iteration_client_specific).start()
 
        return iteration_client_specific[:pos_start] + iteration_client_specific[pos_end + 1:]
 
    else:
        # software data
        return iteration_client_specific

def main():
    

    system_folder_containing_wasserstein_distances = pathlib.Path(r"\computing results\wasserstein_distance_v1_17_02_2025")
    file_names = [file_name for folder_content in os.walk(system_folder_containing_wasserstein_distances) for file_name in folder_content[2]]

    results = []
    
    for idx, file in enumerate(file_names):
        current_data_load = pd.read_csv(pathlib.Path.joinpath(system_folder_containing_wasserstein_distances, file))
        current_results_list = current_data_load.values.tolist()

        for entry in current_results_list:
            results.append(entry)

    data = pd.DataFrame(results, columns=["d_s_1", "d_s_2", "Wasserstein_Distance_Normalized", "Wasserstein_Distance_Not_Normalized"])

    data['d_s_1'] = data['d_s_1'].str.replace("simdata_hardware_sim23_", "")
    data['d_s_1'] = data['d_s_1'].str.replace("simdata_software_sim23_rerun", "Software_Sim_23_")
    data['d_s_1'] = data['d_s_1'].str.replace("_converted_and_labeled_data.gz", "")
    data['d_s_1'] = data['d_s_1'].str.replace("Hardware_Sim_23_Run", "hw_run")
    data['d_s_1'] = data['d_s_1'].str.replace("iteration", "itr")
    data['d_s_1'] = data['d_s_1'].str.replace("SimUser00", "c_")
    data['d_s_1'] = data['d_s_1'].str.replace("Software_Sim_23__rerun", "sw_run")
    data['d_s_1'] = data['d_s_1'].apply(remove_itr_idx)
    data['d_s_1'] = data['d_s_1'].str.replace("__", "_")

    data['d_s_2'] = data['d_s_2'].str.replace("simdata_hardware_sim23_", "")
    data['d_s_2'] = data['d_s_2'].str.replace("simdata_software_sim23_rerun", "Software_Sim_23_")
    data['d_s_2'] = data['d_s_2'].str.replace("_converted_and_labeled_data.gz", "")
    data['d_s_2'] = data['d_s_2'].str.replace("Hardware_Sim_23_Run", "hw_run")
    data['d_s_2'] = data['d_s_2'].str.replace("iteration", "itr")
    data['d_s_2'] = data['d_s_2'].str.replace("SimUser00", "c_")
    data['d_s_2'] = data['d_s_2'].str.replace("Software_Sim_23__rerun", "sw_run")
    data['d_s_2'] = data['d_s_2'].apply(remove_itr_idx)
    data['d_s_2'] = data['d_s_2'].str.replace("__", "_")

    data = pd.pivot_table(data=data, values="Wasserstein_Distance_NotNormalized", index="d_s_1", columns="d_s_2")

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.set(font_scale=1.3)
    sns.heatmap(data).set_title("Wasserstein Distances Of Windows 10 Security Auditing EventID Frequency Counts")
    plt.show()
    return 0

if __name__ == "__main__":
    main()