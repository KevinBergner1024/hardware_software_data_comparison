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
from sklearn.model_selection import cross_validate, StratifiedKFold
from sklearn.utils import shuffle
from sklearn.preprocessing import LabelEncoder
import numpy as np
from sklearn.preprocessing import MinMaxScaler

NAME = "WSAL MACHINE LEARNING SCRIPT"
VERSION = "1.4"
CMD_MODE_ENABLED = True

SUPERVISED_MODELS = {
                    'Bagging-KNN' : BaggingClassifier(KNeighborsClassifier(n_neighbors=3,n_jobs=1),n_estimators=10, max_samples=1000, n_jobs=1),
                    'DTree' : DecisionTreeClassifier(),
                    'RF' : RandomForestClassifier(n_jobs=1),
                    'Bagging-SVM':  BaggingClassifier(SVC(C=0.5), n_estimators=10, max_samples=1000, n_jobs=1),
                    'MLP':  MLPClassifier(alpha=0.0001, max_iter=50, random_state=42),
                    'XGBoost': xgb.XGBClassifier(n_jobs=1),
                    }

def evaluate_model(X_train:np.array, X_test:np.array, y_train:np.array, y_test:np.array, encoding_name:str, data_set_name:str, path_to_store_results:pathlib.Path, models:dict = SUPERVISED_MODELS):
    """evaluate machine learning models based on predefined data split strategy
    Args:
        X_train (np.array): windows security audit logs encoded training data
        X_test (np.array): windows security audit logs encoded test data
        y_train (np.array): windows security audit logs encoded training labels
        y_test (np.array): windows security audit logs encoded testing labels
        encoding_name (str): name of data encoding
        data_set_name (str): name of data set
        path_to_store_results (pathlib.Path): system path to store ml model performance evaluation
        models (dict, optional): machine learning models used . Defaults to SUPERVISED_MODELS.
    """
    
    logging.basicConfig(filename=pathlib.Path(__file__).with_name('machine_learning.log'), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
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
        report = classification_report(y_true=y_test, y_pred=y_pred, zero_division=0, output_dict=True)
        report = pd.DataFrame([report])
        report.to_csv(pathlib.Path.joinpath(path_to_store_results, "train_test_split" + "_" + "classification_report" + "_" + encoding_name + '_' + data_set_name + '_' + clf_name + '.csv'))

def run_kfold_cross(X:np.array, y:np.array, encoding_name:str, data_set_name:str, path_to_store_results:pathlib.Path, models:dict = SUPERVISED_MODELS, cv_mode:str="normal_cv_mode", k_folds:int=5):
    """run k-fold cross validation for encoded data set and store evaluation results afterwards
    Args:
        X (np.array): encoded windows security audit logs data
        y (np.array): encoded windows security audit logs labels
        encoding_name (str): name of data encoding
        data_set_name (str): name of data set used for cross validation
        models (dict, optional): selection of machine learning models to train and test on encoded data set. Defaults to SUPERVISED_MODELS.
        path_to_store_results (pathlib.Path): system path to store machine learning models results. Defaults to None.
        cv_mode (str, optional): mode for applying cross validation (two options: normal_cv_mode, stratified_cv_mode). Defaults to "normal_cv_mode".
        k_folds (int, optional): number of folds to use in cross validation setup. Defaults to 5.
    """

    logging.basicConfig(filename=pathlib.Path(__file__).with_name('machine_learning.log'), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
    # iterate based on SUPERVISED_MODELS global parameter
    for clf_name, clf in models.items():
        logging.debug('| %s | %s | %s',  clf_name, encoding_name , data_set_name)
     
        scoring = {
                'Acc': 'accuracy',
                'Prec-weighted': 'precision_weighted',
                'Rec-weighted': 'recall_weighted',
                'F1-weighted': 'f1_weighted',
            }
            
        applied_cv_mode = k_folds

        if(cv_mode == "stratified_cv_mode"):
             applied_cv_mode = StratifiedKFold(n_splits=k_folds)

        scores = cross_validate(clf, X, y, scoring=scoring, cv=applied_cv_mode, return_train_score=False, verbose=1, n_jobs=1)

        scores = pd.DataFrame(scores)
        scores['model'] = clf_name
        scores['dataset'] = data_set_name
        scores['dataset_count_rows'] = X.shape[0]
        scores['encoding'] = encoding_name
        
        scores.to_csv(pathlib.Path.joinpath(pathlib.Path(path_to_store_results), cv_mode + "_" + encoding_name + '_' + data_set_name + '_' + clf_name + '.csv'))

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