import argparse
import textwrap
import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import CountVectorizer

NAME = "WSAL MACHINE LEARNING ENCODING SCRIPT"
VERSION = 1.0
CMD_MODE_ENABLED = False

def encode_wsal_data_container_time_window_based_event_ids_only(data:pd.DataFrame, frequence : str = "s"):
    """encoding Windows 10 security audit logs for machine learning classification 

    Args:
        data (pd.DataFrame): data to encode
        frequence (str): size of fixed time window used to implement event frequency count. Defaults to "s".

    Returns:
        data (pd.DataFrame): encoded Windows 10 security audit log data
    """
    # idea from https://www.sciencedirect.com/science/article/pii/S2666827023000233
    data_without_labels = data[['SYSTEM_TimeCreated', 'SYSTEM_EventID']].copy()
    # one-hot-encoding for included eventIDs
    data_without_labels = pd.get_dummies(data_without_labels, columns=['SYSTEM_EventID'], dtype=int)
    # count one hot encoded data feature values of SYSTEM_EventID by time range grouping
    data_without_labels = data_without_labels.groupby(pd.Grouper(key="SYSTEM_TimeCreated", freq=frequence, axis=0)).sum()
    data_without_labels['SYSTEM_TimeCreated'] = data_without_labels.index
    final_data = data_without_labels.reset_index(drop=True)
    
    data_without_event_ids = data[['SYSTEM_TimeCreated', 'Labels']].copy()
    data_without_event_ids = data_without_event_ids.groupby(pd.Grouper(key="SYSTEM_TimeCreated", freq=frequence, axis=0))['Labels'].apply(set)
    data_without_event_ids = data_without_event_ids.astype(str)
    data_without_event_ids = data_without_event_ids.reset_index(drop=True)

    final_data['Labels'] = data_without_event_ids.values

    # get indices of all columns which include event ids
    col_event_id_indices = [index for index, value in enumerate(final_data.columns.values.tolist()) if "SYSTEM_EventID" in value]
    
    # remove zero value rows | axis: 1 / ‘columns’ : reduce the columns, return a Series whose index is the original index.
    # based on time window implementation also non-event time slots are generated with no events and empty labels -> those need to be removed
    final_data = final_data.loc[(final_data[final_data.iloc[:, col_event_id_indices] != 0]).any(axis=1)]

    return final_data

def main():
    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog=NAME, formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent(('''
        This script is called by main experiment script (wsal_machine_learning_script.py) on highest hierachy of this repository structure.
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