import pandas as pd
import pathlib
import os
import matplotlib.pylab as plt
import seaborn as sns


def main():
    

    system_folder_containing_wasserstein_distances = pathlib.Path(r"C:\Users\kev8693m\database\research_projects\data_set_hard_software_sim_comparison\computing results\wasserstein_distance_v1_17_02_2025")
    file_names = [file_name for folder_content in os.walk(system_folder_containing_wasserstein_distances) for file_name in folder_content[2]]

    results = []
    
    for idx, file in enumerate(file_names):
        current_data_load = pd.read_csv(pathlib.Path.joinpath(system_folder_containing_wasserstein_distances, file))
        current_results_list = current_data_load.values.tolist()

        for entry in current_results_list:
            results.append(entry)

    data = pd.DataFrame(results, columns=["First_Data_Set_Name", "Second_Data_Set_Name", "Wasserstein_Distance_Normalized", "Wasserstein_Distance_Not_Normalized"])

    data['First_Data_Set_Name'] = data['First_Data_Set_Name'].str.replace("simdata_hardware_sim23_", "")
    data['First_Data_Set_Name'] = data['First_Data_Set_Name'].str.replace("simdata_software_sim23_rerun", "Software_Sim_23_")
    data['First_Data_Set_Name'] = data['First_Data_Set_Name'].str.replace("_converted_and_labeled_data.gz", "")

    data['Second_Data_Set_Name'] = data['Second_Data_Set_Name'].str.replace("simdata_hardware_sim23_", "")
    data['Second_Data_Set_Name'] = data['Second_Data_Set_Name'].str.replace("simdata_software_sim23_rerun", "Software_Sim_23_")
    data['Second_Data_Set_Name'] = data['Second_Data_Set_Name'].str.replace("_converted_and_labeled_data.gz", "")

    data = pd.pivot_table(data=data, values="Wasserstein_Distance_Normalized", index="First_Data_Set_Name", columns="Second_Data_Set_Name")

    sns.heatmap(data)
    plt.show()
    return 0

if __name__ == "__main__":
    main()