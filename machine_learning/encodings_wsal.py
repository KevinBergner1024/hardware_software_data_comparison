import argparse
import textwrap
import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import CountVectorizer

NAME = "WSAL BAG OF WORDS ENCODING SCRIPT"
VERSION = 1.0
CMD_MODE_ENABLED = False

def get_csr_memory_usage(matrix):
    BYTES_TO_MB_DIV = 0.000001
    mem = (matrix.data.nbytes + matrix.indptr.nbytes + matrix.indices.nbytes) * BYTES_TO_MB_DIV
    print("Memory usage is " + str(mem) + " MB")

def encode_wsal_data_container_bag_of_words(data:pd.DataFrame):
    data["DELIMITER"] = "DELIMITER_SELF_DEFINED_GENESIS"
    # idea from https://www.sciencedirect.com/science/article/pii/S2666827023000233
    data_as_string = data.to_string(header=False, index=False, index_names=False).replace("\\", "").replace("\n", "")
    # add special delimiter for splitting
    data_as_string_splitted = data_as_string.split("DELIMITER_SELF_DEFINED_GENESIS")
    # regex expression []+
    vectorizer = CountVectorizer(token_pattern='[a-zA-Z0-9${}&+,:;=?@#|<>.^*()%!-]+')
    data_bow_scipy_sparse_csr_csr_matrix = vectorizer.fit_transform(data_as_string_splitted)
    wsal_vocab = vectorizer.get_feature_names()

    return data_bow_scipy_sparse_csr_csr_matrix, wsal_vocab

def encode_wsal_data_container_time_window_based_event_ids_only_backup(data:pd.DataFrame, frequence : str = "s"):
    # idea from https://www.sciencedirect.com/science/article/pii/S2666827023000233
    data = data[['SYSTEM_TimeCreated', 'SYSTEM_EventID', 'Labels']]
    print("loaded shortened data")
    # one-hot-encoding for included eventIDs
    data_new = pd.get_dummies(data, columns=['SYSTEM_EventID', 'Labels'], dtype=int)
    print("dummy data generation done")
    # count one hot encoded data feature values of SYSTEM_EventID and Labels by time range grouping
    new_data = data_new.groupby(pd.Grouper(key="SYSTEM_TimeCreated", freq=frequence, axis=0)).sum()
    print("data group by done")
    new_data['SYSTEM_TimeCreated'] = new_data.index
    new = new_data.reset_index(drop=True)
    
    # get indices of all columns which include event ids
    col_event_id_indices = [index for index, value in enumerate(new.columns.values.tolist()) if "SYSTEM_EventID" in value]
    # remove zero value rows | axis: 1 / ‘columns’ : reduce the columns, return a Series whose index is the original index.
    data_grouped_without_zero_rows_for_event_ids = new.loc[(new[new.iloc[:, col_event_id_indices] != 0]).any(axis=1)]

    # get column indies of one-hot encoded & grouped by SYSTEM_TimeCreated label values
    col_labels_indices = [index for index, value in enumerate(new.columns.values.tolist()) if "Labels" in value]

    # limited number of iteration based on limited number of labels in data set
    for col_label_idx in col_labels_indices:
        # get col name
        col_name = data_grouped_without_zero_rows_for_event_ids.iloc[:,col_label_idx].name 
        # assign col name to non zero label count values for grouping range
        data_grouped_without_zero_rows_for_event_ids.iloc[:,col_label_idx][data_grouped_without_zero_rows_for_event_ids.iloc[:,col_label_idx] > 0] = col_name
        # create dummy tag for zero values count for grouping range
        data_grouped_without_zero_rows_for_event_ids.iloc[:,col_label_idx].replace(0, "dummy", inplace=True)

    print("dummy convertion done")
    labels = data_grouped_without_zero_rows_for_event_ids.iloc[:, col_labels_indices].to_string(header=False, index=False, index_names=False).replace("dummy", "").replace(" ", "").split("\n")
    print("tostring operating for df done")
    data_grouped_without_zero_rows_for_event_ids['Labels'] = labels
    data_grouped_without_zero_rows_for_event_ids.drop(data_grouped_without_zero_rows_for_event_ids.columns[col_labels_indices], axis=1, inplace=True)

    return data_grouped_without_zero_rows_for_event_ids

def encode_wsal_data_container_time_window_based_event_ids_only(data:pd.DataFrame, frequence : str = "s"):
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