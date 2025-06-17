import argparse
import textwrap
import pandas as pd
import xgboost as xgb
import pathlib
import logging
import numpy as np 

from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, classification_report
from sklearn.ensemble import RandomForestClassifier , BaggingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier

NAME = "WSAL CLASSIFICATION MACHINE LEARNING MODELS SCRIPT"
VERSION = "1.4"
CMD_MODE_ENABLED = True

SUPERVISED_MODELS = {
                    'Bagging-KNN' : BaggingClassifier(KNeighborsClassifier(n_neighbors = 3, n_jobs = 1), n_estimators = 10, max_samples =  1000, n_jobs = 1),
                    'DTree' : DecisionTreeClassifier(),
                    'RF' : RandomForestClassifier(n_jobs = 1),
                    'Bagging-SVM':  BaggingClassifier(SVC(C= 0.5), n_estimators = 10, max_samples = 1000, n_jobs = 1),
                    'MLP':  MLPClassifier(alpha = 0.0001, max_iter = 50, random_state = 42),
                    'XGBoost': xgb.XGBClassifier(n_jobs = 1),
                    }

def evaluate_model(X_train: np.array, X_test: np.array, y_train: np.array, y_test: np.array, encoding_name: str, data_set_name: str, path_to_store_results: pathlib.Path, models: dict = SUPERVISED_MODELS):
    """evaluate machine learning models based on predefined data split strategy
    Args:
        X_train (np.array): Windows 10 security audit logs encoded training data
        X_test (np.array): Windows 10 security audit logs encoded test data
        y_train (np.array): Windows 10 security audit logs encoded training labels
        y_test (np.array): Windows 10 security audit logs encoded testing labels
        encoding_name (str): name of data encoding
        data_set_name (str): name of data set
        path_to_store_results (pathlib.Path): system path to store ml model performance evaluation
        models (dict): machine learning models used . Defaults to SUPERVISED_MODELS.
    """
    logging.basicConfig(filename = pathlib.Path(__file__).with_name('machine_learning.log'), level = logging.DEBUG, format = '%(asctime)s - %(levelname)s - %(message)s', datefmt = "%d/%m/%Y %H:%M:%S")
    for clf_name, clf in models.items():
        logging.debug('| %s | %s | %s',  clf_name, encoding_name , data_set_name)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        scores = {
                'evaluate_model_acc' : accuracy_score(y_test, y_pred),
                'evaluate_model_precision-weighted' : precision_score(y_test, y_pred, average='weighted'),
                'evaluate_model_recall-weighted' : recall_score(y_test, y_pred, average='weighted'),
                'evaluate_model_f1-weighted' : f1_score(y_test, y_pred, average='weighted')
                }
        
        scores = pd.DataFrame([scores])
        scores['model'] = clf_name
        scores['dataset'] = data_set_name
        scores['dataset_count_rows_train_data'] = X_train.shape[0]
        scores['dataset_count_rows_test_data'] = X_test.shape[0]
        scores['encoding'] = encoding_name
        scores.to_csv(pathlib.Path.joinpath(path_to_store_results, "train_test_split_" + encoding_name + '_' + data_set_name + '_' + clf_name + '.csv'))
        # classification report for detailed information about class specific performance info
        report = classification_report(y_true = y_test, y_pred = y_pred, zero_division = 0, output_dict = True)
        report = pd.DataFrame([report])
        report.to_csv(pathlib.Path.joinpath(path_to_store_results, "train_test_split" + "_" + "classification_report" + "_" + encoding_name + '_' + data_set_name + '_' + clf_name + '.csv'))

def main():
    return 0

if __name__ == "__main__":
    if(CMD_MODE_ENABLED):
        parser = argparse.ArgumentParser(prog = NAME, formatter_class = argparse.RawDescriptionHelpFormatter, description = textwrap.dedent(('''
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