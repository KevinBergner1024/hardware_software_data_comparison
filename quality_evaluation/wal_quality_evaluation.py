import textwrap
import argparse
import datetime
import pandas as pd
import logging
import pathlib
import configparser

NAME = "Windows Audit Logs Quality Evaluation Script"
VERSION = "1.11"
CMD_MODE_ENABLED = False
SIM_USER_DUMMY_TAG = "SIM_USER_DUMMY"

LABEL_WAL_FEATURE_MAPPING = {
    # process name & count of files included in general encrypt attack
    'encrypt_copy_200KB_10_files' : ['C:\\Windows\\System32\\xcopy.exe', 10],
    'encrypt_encrypt_200KB_10_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 10],
    'encrypt_decrypt_200KB_10_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 10],
    'encrypt_copy_200KB_100_files' : ['C:\\Windows\\System32\\xcopy.exe', 100],
    'encrypt_encrypt_200KB_100_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 100],
    'encrypt_decrypt_200KB_100_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 100],
    'encrypt_copy_200KB_1000_files' : ['C:\\Windows\\System32\\xcopy.exe', 1000],
    'encrypt_encrypt_200KB_1000_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1000],
    'encrypt_decrypt_200KB_1000_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1000],
    'encrypt_copy_10MB_10_files' : ['C:\\Windows\\System32\\xcopy.exe', 10],
    'encrypt_encrypt_10MB_10_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 10],
    'encrypt_decrypt_10MB_10_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 10],
    'encrypt_copy_10MB_100_files' : ['C:\\Windows\\System32\\xcopy.exe', 100],
    'encrypt_encrypt_10MB_100_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 100],
    'encrypt_decrypt_10MB_100_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 100],
    'encrypt_copy_10MB_1000_files' : ['C:\\Windows\\System32\\xcopy.exe', 1000],
    'encrypt_encrypt_10MB_1000_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1000],
    'encrypt_decrypt_10MB_1000_files' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1000],
    'encrypt_copy_1GB_1_file' : ['C:\\Windows\\System32\\xcopy.exe', 1],
    'encrypt_encrypt_1GB_1_file' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1],
    'encrypt_decrypt_1GB_1_file' : ['C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', 1],
    # object name (net or local copy), count of file to copy
    'copy_local_to_local_1_files_each_1GB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\gross\\wenig', 1],
	'copy_local_to_local_10_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\wenig', 10],
	'copy_local_to_local_10_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\wenig', 10],
	'copy_local_to_local_100_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\mittel', 100],
	'copy_local_to_local_100_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\mittel', 100],
	'copy_local_to_local_1000_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\viel', 1000],
	'copy_local_to_local_1000_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\viel', 1000],
	'copy_net_to_local_1_files_each_1GB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\gross\\wenig', 1],
	'copy_net_to_local_10_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\wenig', 10],
	'copy_net_to_local_10_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\wenig', 10],
	'copy_net_to_local_100_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\mittel', 100],
	'copy_net_to_local_100_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\mittel', 100],
	'copy_net_to_local_1000_files_each_200KB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\klein\\viel', 1000],
	'copy_net_to_local_1000_files_each_10MB_delete_files_after_copy_included' : ['C:\\localstorage\\sim23_dest\\mittel\\viel', 1000]
}

def load_config_asset(config_section:str, config_key:str, config_system_path:pathlib.Path=pathlib.Path(__file__).with_name('config.ini')):
    """load configuration content from config file

    Args:
        config_section (str): section in config file
        config_key (str): key value of config section
        config_system_path (pathlib.Path, optional): system path to config file

    Returns:
        str: configuration value queried for
    """
    try:
        config_object = configparser.ConfigParser()
        config_object.read(config_system_path)
        config_section = config_object[config_section]
        config_key_value = config_section[config_key]
    except:
        print("METHOD: load_config_asset throws exception!")

    return config_key_value

def quality_check_programming_behavior_java(wal_dataframe:pd.DataFrame, start_timestamp_programming_behavior:datetime.datetime, end_timestamp_programming_behavior:datetime.datetime,
                                            delete_file_initially_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', delete_file_initially_event_id:str='4663', delete_file_initially_object_name:str='C:\\workspace\\Unmanaged\\JavaSim23\\Sim23.java', delete_file_initially_access_type:str='%%1537',
                                            create_java_template_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', create_java_template_file_event_id:str='4663', create_java_template_file_object_name:str='C:\\workspace\\Unmanaged\\JavaSim23\\Sim23.java', create_java_template_file_access_type:str='%%4417',
                                            create_java_file_loc_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', create_java_file_loc_event_id:str='4663', create_java_file_loc_object_name:str='C:\\workspace\\Unmanaged\\JavaSim23\\Sim23.java', create_java_file_loc_access_type:str='%%4417',
                                            compile_delete_class_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', compile_delete_class_file_event_id:str='4663', compile_delete_class_file_object_name:str='C:\\workspace\\Unmanaged\\JavaSim23\\Sim23.class', compile_delete_class_file_access_type:str='%%1537',
                                            compile_create_class_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.1-12\\bin\\javac.exe', compile_create_class_file_event_id:str='4663', compile_create_class_file_object_name:str='C:\\workspace\\Unmanaged\\JavaSim23\\Sim23.class', compile_create_class_file_access_type:str='%%4417',
                                            execute_sim23_class_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.1-12\\bin\\java.exe', execute_sim23_class_file_event_id:str='4663', execute_sim23_class_file_object_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.1-12\\bin\\server\\jvm.dll', execute_sim23_class_file_access_type:str='%%4421',
                                            log_wal_quality_evaluation:bool=True, sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None, sim_user_of_interest:str=None):
    
     #C:\Users\SimUser001\scoop\apps\openjdk\21.0.1-12\bin\javac.exe  (new one)
     #C:\\Users\\SimUser001\\scoop\\apps\\openjdk\\20.0.1-9\\bin\\javac.exe (older one)
     # for softsim SimUser003 C:\Users\SimUser003\scoop\apps\openjdk\21.0.2-13\bin\java.exe -> change input parameter in automated wsal evaluation wal_general_quality_check_handler_sim23_log_based method name

    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for java programming behavior sim23

    Args:
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_timestamp_programming_behavior (datetime.datetime): start timestamp of sim23 behavior of interest
        end_timestamp_programming_behavior (datetime.datetime): end timestamp of sim23 behavior of interest
        delete_file_initially_process_name (str): program executable that accessed the object during initial file (.java-file) delete step of java programming behavior
        delete_file_initially_event_id (str): windows security event id of interest of initial file (.java-file) delete step of java programming behavior
        delete_file_initially_object_name (str): name of the object being accessed during initial file (.java-file) delete step of java programming behavior
        delete_file_initially_access_type (str): access type included in windows security event of initial file (.java-file) delete step of java programming behavior
        create_java_template_file_process_name (str):  program executable that accessed the object during creation of file template (.java-file)
        create_java_template_file_event_id (str): windows security event id of interest during creation of file template (.java-file)
        create_java_template_file_object_name (str): name of object being accessed during creation of file template (.java-file)
        create_java_template_file_access_tpye (str): access type included in windows security event while creating file template (.java-file)
        create_java_file_loc_process_name (str): program executable that accessed the object while creating the file (.java-file) which includes lines of code
        create_java_file_loc_event_id (str): windows security event id of interest while creating the file (.java-file) which includes lines of code
        create_java_file_loc_object_name (str): name of object being access while creating the file (.java-file) which includes lines of code 
        create_java_file_loc_access_type (str): access type included in windows security event while creating the file (.java-file) which includes lines of code
        compile_delete_class_file_process_name (str): program executable that accessed the object during deletion of file (.class-file) while compling java code
        compile_delete_class_file_event_id (str): windows security event id of interest during deletion of file (.class-file) while compling java code
        compile_delete_class_file_object_name (str): name of object being accessed during deletion of file (.class-file) while compiling java code
        compile_delete_class_file_access_type (str): access type included in windows security event during deletion of file (.class-file) while compiling java code
        compile_create_class_file_process_name (str): program executable that accessed the object while creating a new file (.class-file) while compiling java code
        compile_create_class_file_event_id (str): windows event id of interest while creating file (.class-file)while compiling java code
        compile_create_class_file_object name (str): name of object that is being access while creating file (.class-file) while compiling java code
        compile_create_class_file_access_type (str): access type included in windows security event while creating file (.class-file) while compiling java code
        execute_sim23_class_file_process_name (str): porgram executable which executes the java binary
        execute_sim23_class_file_event_id (str): windows security event id of interest during execution of java code
        execute_sim23_class_file_object_name (str): name of object that is being access while executing java code
        execute_sim23_class_file_access_type (str):access type included in windows security event during executing java code
        log_wal_quality_evaluation (bool): log quality check results in log file if True, else no logging will be applied
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)
        sim_user_of_interest (str): name of simulation user which is focused in quality check

    Returns:
        list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """   
    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_programming_behavior_java started')

    # configure path based on given SimUser tag first (001 - 004)
    delete_file_initially_process_name = delete_file_initially_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    create_java_template_file_process_name = create_java_template_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    create_java_file_loc_process_name = create_java_file_loc_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    compile_delete_class_file_process_name = compile_delete_class_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    compile_create_class_file_process_name = compile_create_class_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    execute_sim23_class_file_process_name = execute_sim23_class_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    execute_sim23_class_file_object_name = execute_sim23_class_file_object_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)

    # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events (this value can be true even if the first value is false)
    quality_evaluation_results = [True, True]
    windows_security_log_event_sequence_to_expect = [[delete_file_initially_process_name, delete_file_initially_event_id, delete_file_initially_object_name],
                                            [create_java_template_file_process_name, create_java_template_file_event_id, create_java_template_file_object_name],
                                            [create_java_file_loc_process_name, create_java_file_loc_event_id, create_java_file_loc_object_name],
                                            [compile_delete_class_file_process_name, compile_delete_class_file_event_id, compile_delete_class_file_object_name], 
                                            [compile_create_class_file_process_name, compile_create_class_file_event_id, compile_create_class_file_object_name],
                                            [execute_sim23_class_file_process_name, execute_sim23_class_file_event_id, execute_sim23_class_file_object_name],
                                            [execute_sim23_class_file_process_name, execute_sim23_class_file_event_id, execute_sim23_class_file_object_name]]
    # explicitly check for access type because security event can contain more than one specific access type in access list
    security_access_type_sequence_to_expect = [delete_file_initially_access_type, create_java_template_file_access_type, create_java_file_loc_access_type, compile_delete_class_file_access_type, compile_create_class_file_access_type, execute_sim23_class_file_access_type, execute_sim23_class_file_access_type]
    
    # check if wal_dataframe is empty, if yes skip the quality check part
    if(not wal_dataframe.empty):
        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_timestamp_programming_behavior) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_timestamp_programming_behavior)].copy()

        delete_sim23_java_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == delete_file_initially_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == delete_file_initially_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == delete_file_initially_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(delete_file_initially_access_type))]
        
        create_sim23_java_template_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == create_java_template_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == create_java_template_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == create_java_template_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(create_java_template_file_access_type))]
        
        wal_pattern_programming_java = pd.concat([delete_sim23_java_file_sub_dataframe, create_sim23_java_template_file_sub_dataframe], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)
        create_sim23_java_file_loc_content_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == create_java_file_loc_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == create_java_file_loc_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == create_java_file_loc_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(create_java_file_loc_access_type))]
        
        wal_pattern_programming_java = pd.concat([wal_pattern_programming_java, create_sim23_java_file_loc_content_sub_dataframe], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)
        
        delete_sim23_class_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == compile_delete_class_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == compile_delete_class_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == compile_delete_class_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(compile_delete_class_file_access_type))]
        
        wal_pattern_programming_java = pd.concat([wal_pattern_programming_java, delete_sim23_class_file_sub_dataframe], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        create_sim23_class_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == compile_create_class_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == compile_create_class_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == compile_create_class_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(compile_create_class_file_access_type))]
        
        wal_pattern_programming_java = pd.concat([wal_pattern_programming_java, create_sim23_class_file_sub_dataframe], axis=0, ignore_index= True).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        # java -version (calls jvm.dll)
        # java sim23.behvaior (calls jvm.dll) 
        # will return two entries for this filter criteria based on two java commands: java -version & java sim23.class execution
        execute_sim23_class_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == execute_sim23_class_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == execute_sim23_class_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == execute_sim23_class_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(execute_sim23_class_file_access_type))]

        wal_pattern_programming_java = pd.concat([wal_pattern_programming_java, execute_sim23_class_file_sub_dataframe], axis=0, ignore_index= True).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        #bot subbehavior: create java template & fill java template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well -> drop duplicates
        # granularity based on timestamp feature values: 2023-12-26 20:02:20.906489800 -> the same timestamps should not occur in this order
        wal_pattern_programming_java_without_duplicates = wal_pattern_programming_java.drop_duplicates(ignore_index=True)
        
        security_event_seuqence_to_check = wal_pattern_programming_java_without_duplicates[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_programming_java_without_duplicates[['EVENTDATA_AccessList']].values.flatten().tolist()

        # get start index of sequence to check buffering unexpected simulation behavior at the start and end of the sequences to check
        first_element_of_security_event_sequence_to_expect = windows_security_log_event_sequence_to_expect[0]
        start_index_quality_check= 0
        # iterate over security event sequence to check
        for idx, element in enumerate(security_event_seuqence_to_check):
            if(element == first_element_of_security_event_sequence_to_expect):
                start_index_quality_check = idx
                # stop when start index is found
                break
        
        if((len(security_event_seuqence_to_check[start_index_quality_check:]) >= len(windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check[start_index_quality_check:]) >= len(security_access_type_sequence_to_expect))):
            # security event sequence order and count of event is check at the same type for this behvaior
            for idx, event_row in enumerate(windows_security_log_event_sequence_to_expect):
                if(windows_security_log_event_sequence_to_expect[idx] != security_event_seuqence_to_check[start_index_quality_check + idx]):
                    quality_evaluation_results[0] = False
            # explicitly check for access type because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(security_access_type_sequence_to_expect):
                if(not(security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[start_index_quality_check + idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        # if wal_dataframe is empty
        wal_pattern_programming_java_without_duplicates = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        if(not wal_pattern_programming_java_without_duplicates.empty):
            # first step initial delete java file
            if(delete_sim23_java_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'initial delete java file count of filtered row entries' , 0 , "out of 1 entry/entries expected")
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'initial delete java file count of filtered row entries' , delete_sim23_java_file_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            # second step create java template file
            if(create_sim23_java_template_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java template file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # create java template & fill java template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java template file count of filtered row entries' , create_sim23_java_template_file_sub_dataframe.shape[0], "out of 2 entry/entries expected")
            # thrid step create java file content with loc
            if(create_sim23_java_file_loc_content_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java loc file content count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # create java template & fill java template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java loc file content count of filtered row entries' , create_sim23_java_file_loc_content_sub_dataframe.shape[0], "out of 2 entry/entries expected")
            # fourth step delete java class file
            if(delete_sim23_class_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete java class file count of filtered row entries' , 0, "out of 1 entry/entries expected")
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete java class file count of filtered row entries' , delete_sim23_class_file_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            # fifth step create java class file
            if(create_sim23_class_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java class file count of filtered row entries' , 0, "out of 1 entry/entries expected")
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java class file count of filtered row entries' , create_sim23_class_file_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            # sixth step execute java class file
            if(execute_sim23_class_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute java class file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # will log two entries for this filter criteria based on two java commands: java -version & java sim23.class execution
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute java class file count of filtered row entries' , execute_sim23_class_file_sub_dataframe.shape[0], "out of 2 entry/entries expected")
            
            # final log entry to sum up results -> difference is in logging tag (info & error)
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_programming_java_without_duplicates['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_programming_java_without_duplicates['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_programming_java_without_duplicates['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_programming_java_without_duplicates['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'initial delete java file count of filtered row entries' , 0 , "out of 1 entry/entries expected")
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java template file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java loc file content count of filtered row entries' , 0, "out of 2 entry/entries expected")
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete java class file count of filtered row entries' , 0, "out of 1 entry/entries expected")
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create java class file count of filtered row entries' , 0, "out of 1 entry/entries expected")
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute java class file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            # final log entry to sum up results
            logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "emtpy dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))

    return quality_evaluation_results
    
def quality_check_programming_behavior_python(wal_dataframe:pd.DataFrame, start_timestamp_programming_behavior:datetime.datetime, end_timestamp_programming_behavior:datetime.datetime,
                                              delete_file_initially_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', delete_file_initially_event_id:str='4663', delete_file_initially_object_name:str='C:\\workspace\\Unmanaged\\PythonSim23\\sim23.py', delete_file_initially_access_type:str='%%1537',
                                              create_python_template_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', create_python_template_file_event_id:str='4663', create_python_template_file_object_name:str='C:\\workspace\\Unmanaged\\PythonSim23\\sim23.py', create_python_template_file_access_type:str='%%4417',
                                              create_python_file_loc_content_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', create_python_file_loc_content_event_id:str='4663', create_python_file_loc_content_object_name:str='C:\\workspace\\Unmanaged\\PythonSim23\\sim23.py', create_python_file_loc_content_access_type:str='%%4417',  
                                              execute_python_file_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', execute_python_file_event_id:str='4663', execute_python_file_object_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python311.dll', execute_python_file_access_type:str='%%4421',
                                              log_wal_quality_evaluation:bool=True, sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None, sim_user_of_interest:str=None):
    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for python programming behavior sim23

    Args:
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_timestamp_programming_behavior (datetime.datetime): start timestamp of sim23 behavior of interest
        end_timestamp_programming_behavior (datetime.datetime): end timestamp of sim23 behavior of interest
        delete_file_initially_process_name (str): program executable that accessed the object during initial file (.py-file) delete step of python programming behavior
        delete_file_initially_event_id (str): windows security event id of interest during initial file (.py-file) delete step of python programming behavior
        delete_file_initially_object_name (str): name of object being accessed during initial file (.py-file) delete step of python programming behavior
        delete_file_initially_access_type (str): access type included in windows security event during initial file (.py-file) delete step of python programming behavior
        create_python_template_file_process_name (str): program executable that accessed the object during template file (.py-file) creation of python programming behavior
        create_python_template_file_event_id (str): windows security event id of interest during template file (.py-file) creation of python programming behavior
        create_python_template_file_object_name (str): name of object being accessed during template file (.py-file) creation of python programming behavior
        create_python_template_file_access_type (str): access type included in windows security event during template file (.py-file) creation of python programming behavior
        create_python_file_loc_content_process_name (str): program executable that accessed the object during creating file (.py-file) with lines of code as step of python programming behavior
        create_python_file_loc_content_event_id (str): windows security event id of interest during creating file (.py-file) with lines of code as step of python programming behavior
        create_python_file_loc_content_object_name (str): name of object being accessed during creating file (.py-file) with lines of code as step of python programming behavior
        create_python_file_loc_content_access_type (str): access type included in windows security event during creating file (.py-file) with lines of code as step of python programming behavior
        execute_python_file_process_name (str): program executable that executes python code
        execute_python_file_event_id (str): windows security event id of interest during python code execution
        execute_python_file_object_name (str): name of object being access during python code execution
        execute_python_file_access_type (str): access type included in windows security event during python code execution
        log_wal_quality_evaluation (bool): log quality check results in log file if True, else no logging will be applied
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)
        sim_user_of_interest (str): name of simulation user which is focused in quality check

    Returns:
        list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """

    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_programming_behavior_python started')

    
    # configure path based on given SimUser tag first (001 - 004)
    delete_file_initially_process_name = delete_file_initially_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    create_python_template_file_process_name = create_python_template_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    create_python_file_loc_content_process_name = create_python_file_loc_content_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    execute_python_file_process_name = execute_python_file_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    execute_python_file_object_name = execute_python_file_object_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)

    # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events (this value can be true even if the first value is false)
    quality_evaluation_results = [True, True]

    windows_security_log_event_sequence_to_expect = [[delete_file_initially_process_name, delete_file_initially_event_id, delete_file_initially_object_name],
                                        [create_python_template_file_process_name, create_python_template_file_event_id, create_python_template_file_object_name],
                                        [create_python_file_loc_content_process_name, create_python_file_loc_content_event_id, create_python_file_loc_content_object_name],
                                        [execute_python_file_process_name, execute_python_file_event_id, execute_python_file_object_name]]
    # explicitly check because security event can contain more than one specific access type in access list
    security_access_type_sequence_to_expect = [delete_file_initially_access_type, create_python_template_file_access_type, create_python_file_loc_content_access_type, execute_python_file_access_type] 

    # check if wal_dataframe is empty, if yes skip the quality check part
    if(not wal_dataframe.empty):

        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_timestamp_programming_behavior) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_timestamp_programming_behavior)].copy()

        delete_sim23_python_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == delete_file_initially_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == delete_file_initially_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == delete_file_initially_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(delete_file_initially_access_type))]

        create_sim23_python_template_file_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == create_python_template_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == create_python_template_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == create_python_template_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(create_python_template_file_access_type))]
        
        wal_pattern_programming_python = pd.concat([delete_sim23_python_file_sub_dataframe, create_sim23_python_template_file_sub_dataframe], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        create_sim23_python_file_loc_content = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == create_python_file_loc_content_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == create_python_file_loc_content_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == create_python_file_loc_content_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(create_python_file_loc_content_access_type))]
        
        wal_pattern_programming_python = pd.concat([wal_pattern_programming_python, create_sim23_python_file_loc_content], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        # this filtered event will occur twice based on the inital python behavior script called by the CIDDS-framework & the executed python behavior script executed during this programming behavior
        execute_python_file = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == execute_python_file_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == execute_python_file_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == execute_python_file_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(execute_python_file_access_type))]

        wal_pattern_programming_python = pd.concat([wal_pattern_programming_python, execute_python_file], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        #bot subbehavior: create python template & fill python template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well -> drop duplicates
        wal_pattern_programming_python_without_duplicates = wal_pattern_programming_python.drop_duplicates(ignore_index=True)
        
        security_event_seuqence_to_check = wal_pattern_programming_python_without_duplicates[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_programming_python_without_duplicates[['EVENTDATA_AccessList']].values.flatten().tolist()
        
        # get start index of sequence to check buffering unexpected simulation behavior at the start and end of the sequences to check
        first_element_of_security_event_sequence_to_expect = windows_security_log_event_sequence_to_expect[0]
        start_index_quality_check= 0
        # iterate over security event sequence to check
        for idx, element in enumerate(security_event_seuqence_to_check):
            if(element == first_element_of_security_event_sequence_to_expect):
                start_index_quality_check = idx
                # stop when start index is found
                break
        
        if((len(security_event_seuqence_to_check[start_index_quality_check:]) >= len(windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check[start_index_quality_check:]) >= len(security_access_type_sequence_to_expect))):
            # security event sequence order and count of event is check at the same type for this behvaior
            for idx, event_row in enumerate(windows_security_log_event_sequence_to_expect):
                if(windows_security_log_event_sequence_to_expect[idx] != security_event_seuqence_to_check[start_index_quality_check + idx]):
                    quality_evaluation_results[0] = False
            # explicitly check for access type because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(security_access_type_sequence_to_expect):
                if(not(security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[start_index_quality_check + idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        # if wal_dataframe is empty
        wal_pattern_programming_python_without_duplicates = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        if(not wal_pattern_programming_python_without_duplicates.empty):
            # first step delete python file
            if(delete_sim23_python_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete python file count of filtered row entries' , 0, "out of 1 entry/entries expected")
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete python file count of filtered row entries' , delete_sim23_python_file_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            # second step create python template file
            if(create_sim23_python_template_file_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python template file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # create python template & fill python template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python template file count of filtered row entries' , create_sim23_python_template_file_sub_dataframe.shape[0], "out of 2 entry/entries expected")
            # third step create python file loc content
            if(create_sim23_python_file_loc_content.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python loc file content count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # create python template & fill python template with loc, have same event data features -> due to this both queries aboth included the events of the other behavior as well
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python loc file content count of filtered row entries' , create_sim23_python_file_loc_content.shape[0], "out of 2 entry/entries expected")
            # fourth step execute python file
            if(execute_python_file.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute python file count of filtered row entries' , 0, "out of 2 entry/entries expected")
            else:
                # this filtered event will occur twice based on the inital python behavior script called by the CIDDS-framework & the executed python behavior script executed during this programming behavior
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute python file count of filtered row entries' , execute_python_file.shape[0], "out of 2 entry/entries expected")
            
            # final log entry to sum up results
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_programming_python_without_duplicates['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_programming_python_without_duplicates['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_programming_python_without_duplicates['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_programming_python_without_duplicates['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'delete python file count of filtered row entries' , 0, "out of 1 entry/entries expected")
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python template file count of filtered row entries' , 0, "out of 2 entry/entries expected")
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'create python loc file content count of filtered row entries' , 0, "out of 2 entry/entries expected")
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'execute python file count of filtered row entries' , 0, "out of 2 entry/entries expected")
             # final log entry to sum up results
             logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "empty dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_timestamp_programming_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))

    return quality_evaluation_results
    
def quality_check_copy_local_to_local_and_net_to_local(complete_copy_behavior_object_name:str, number_of_files_to_copy:int, wal_dataframe:pd.DataFrame, start_time_copy_behavior:datetime.datetime, end_time_copy_behavior:datetime.datetime,
                                                       complete_copy_behavior_process_name:str='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe', complete_copy_behavior_event_id:str='4663',
                                                       create_file_while_copy_to_target_dir_access_type:str='%%4417', delete_files_when_copy_to_target_dir_done_access_type:str='%%1537',
                                                       log_wal_quality_evaluation:bool=True, sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None, sim_user_of_interest:str=None):
    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for copy file (local & net) behavior sim23

    Args:
        complete_copy_behavior_object_name (str): name of object being accessed during initial file (.dat-file) creation step of copy behavior (net & local)
        number_of_files_to_copy (int): pre-defined amount of file to copy based on configured sim23 behavior
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_time_copy_behavior (datetime.datetime): start timestamp of sim23 behavior of interest
        end_time_copy_behavior (datetime.datetime): end timestamp of sim23 behavior of interest
        complete_copy_behavior_process_name (str): program executable that accessed the object during create & delete (.dat-file) steps of copy behavior
        complete_copy_behavior_event_id (str): windows security event id of interest during create & delete (.dat-file) steps of copy behavior
        create_file_while_copy_to_target_dir_access_type (str): access type included in windows security event during creating file (.dat-file) as initial step of copy behavior
        delete_files_when_copy_to_target_dir_done_access_type (str): access type included in windows security event during deleting file (.dat-file) as final step of copy behavior
        log_wal_quality_evaluation (bool): log quality check results in log file if True, else no logging will be applied
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)
        sim_user_of_interest (str): name of simulation user which is focused in quality check

    Returns:
        list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """
    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_copy_local_to_local_and_net_to_local started')

    complete_copy_behavior_process_name = complete_copy_behavior_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)

    quality_evaluation_results = [True, True]
    # sequence to expect depends on specifc copy behavior
    # copy and delete have the same features in for process name, event_id, object name
    single_windows_security_log_event_sequence_to_expect = [[complete_copy_behavior_process_name, complete_copy_behavior_event_id, complete_copy_behavior_object_name], [complete_copy_behavior_process_name, complete_copy_behavior_event_id, complete_copy_behavior_object_name]]
    single_security_access_type_sequence_to_expect = [create_file_while_copy_to_target_dir_access_type, delete_files_when_copy_to_target_dir_done_access_type]
    
    # if wal_dataframe is empty skip this quality check part
    if(not wal_dataframe.empty):
        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_time_copy_behavior) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_time_copy_behavior)].copy()
        # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events (this value can be true even if the first value is false)
    
        file_created_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == complete_copy_behavior_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == complete_copy_behavior_event_id) & \
                                                ((dataframe_copy['EVENTDATA_ObjectName'].str.contains(complete_copy_behavior_object_name, regex=False)) & (dataframe_copy['EVENTDATA_ObjectName'].str.contains('.dat'))) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(create_file_while_copy_to_target_dir_access_type))]

        file_deleted_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == complete_copy_behavior_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == complete_copy_behavior_event_id) & \
                                                ((dataframe_copy['EVENTDATA_ObjectName'].str.contains(complete_copy_behavior_object_name, regex=False)) & (dataframe_copy['EVENTDATA_ObjectName'].str.contains('.dat')))& \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(delete_files_when_copy_to_target_dir_done_access_type))]
        
        wal_pattern_copy_behavior = pd.concat([file_created_sub_dataframe, file_deleted_sub_dataframe], axis=0).sort_values(by='SYSTEM_TimeCreated', ignore_index=True)
        
        security_event_seuqence_to_check = wal_pattern_copy_behavior[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_copy_behavior[['EVENTDATA_AccessList']].values.flatten().tolist()
        
        complete_windows_security_log_event_sequence_to_expect = []
        complete_security_access_type_sequence_to_expect = []

        for itr in range(number_of_files_to_copy):
            # update windows security log events sequence
            # execution order: copy all n file then delete all n files (not copy then delete than copy than delete ....)
            complete_windows_security_log_event_sequence_to_expect = complete_windows_security_log_event_sequence_to_expect + [single_windows_security_log_event_sequence_to_expect[1]]
            complete_windows_security_log_event_sequence_to_expect = [single_windows_security_log_event_sequence_to_expect[0]] + complete_windows_security_log_event_sequence_to_expect
            # update windows security access type seuqence
            # execution order: copy all n file then delete all n files (not copy then delete than copy than delete ....)
            complete_security_access_type_sequence_to_expect = complete_security_access_type_sequence_to_expect + [single_security_access_type_sequence_to_expect[1]]
            complete_security_access_type_sequence_to_expect = [single_security_access_type_sequence_to_expect[0]] + complete_security_access_type_sequence_to_expect 

        if((len(security_event_seuqence_to_check) == len(complete_windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check) == len(complete_security_access_type_sequence_to_expect))):
            for idx, event_row in enumerate(complete_windows_security_log_event_sequence_to_expect):
                # explicitly check every element because object file names vary while copying different files
                if((complete_windows_security_log_event_sequence_to_expect[idx][0] != security_event_seuqence_to_check[idx][0]) or (complete_windows_security_log_event_sequence_to_expect[idx][1] != security_event_seuqence_to_check[idx][1]) or (not(complete_windows_security_log_event_sequence_to_expect[idx][2] in security_event_seuqence_to_check[idx][2])) or (not('.dat' in security_event_seuqence_to_check[idx][2]))):
                    quality_evaluation_results[0] = False
            # explicitly check because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(complete_security_access_type_sequence_to_expect):
                if(not(complete_security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        wal_pattern_copy_behavior = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        if(not wal_pattern_copy_behavior.empty):
            description_expected_entries = "out of " + str(number_of_files_to_copy) + " entry/entries expected"
            # first step create files in destination folder
            if(file_created_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files created count of filtered row entries' , 0, description_expected_entries)
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files created count of filtered row entries' , file_created_sub_dataframe.shape[0], description_expected_entries)
            # second step delete files in destination folder
            if(file_deleted_sub_dataframe.empty):
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files deleted count of filtered row entries' , 0, description_expected_entries)
            else:
                logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files deleted count of filtered row entries' , file_deleted_sub_dataframe.shape[0], description_expected_entries)
            
            # final log entry to sum up results
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_copy_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_copy_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_copy_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_copy_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files created count of filtered row entries' , 0, description_expected_entries)
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'files deleted count of filtered row entries' , 0, description_expected_entries)
             # final log entry to sum up results
             logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "empty dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_copy_behavior.strftime("%d/%m/%Y %H:%M:%S:%f"))

    return quality_evaluation_results

def quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt(number_of_files_to_copy_or_encrypt_or_decrypt:int, wal_dataframe:pd.DataFrame, start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt:datetime.datetime, end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt:datetime.datetime,
                           encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name:str, encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type:str, encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name:str='C:\\Windows\\System32\\xcopy.exe', encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_event_id:str='4663',
                           log_wal_quality_evaluation:bool=True, sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None, sim_user_of_interest:str=None):
    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for encrypt copy, encrypt, decrypt behavior sim23

    Args:
        number_of_files_to_copy_or_encrypt_or_decrypt (int): pre-defined amount of files to copy, encrypt or decrypt based on encrypt attack
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt (datetime.datetime):  start timestamp of sim23 behavior of interest
        end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt (datetime.datetime):  end timestamp of sim23 behavior of interest
        encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name (str): name of object being accessed during encrypt copy, encrypt or decrypt of files (.dat-file) while encrypt attack
        encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type (str): access type included in windows security event during encrypt copy, encrypt or decrypt of files (.dat-file) while encrypt attack
        encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name (str): program executable that accessed the object during encrypt copy, encrypt or decrypt of files (.dat-file) while encrypt attack
        encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_event_id (str): windows security event id of interest during encrypt copy, encrypt or decrypt of files (.dat-file) while encrypt attack
        log_wal_quality_evaluation (bool): log quality check results in log file if True, else no logging will be applied
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)
        sim_user_of_interest (str): name of simulation user which is focused in quality check

    Returns:
        list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """
    
    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt started')

    if(not 'encrypt_copy' in sim23_log_behavior_label):
        encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name = encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)

    quality_evaluation_results = [True, True]

    single_windows_security_log_event_sequence_to_expect = [[encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name, encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_event_id, encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name]]
    single_security_access_type_sequence_to_expect = [encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type]

    # if wal_dataframe is empty skip the quality evaluation part
    if(not wal_dataframe.empty):

        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt)].copy()
        # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events (this value can be true even if the first value is false)

        encrypt_copy_or_encrypt_decrpyt_or_encrpyt_encrpyt_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_event_id) & \
                                                ((dataframe_copy['EVENTDATA_ObjectName'].str.contains(encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name, regex=False)) & (dataframe_copy['EVENTDATA_ObjectName'].str.contains('.dat'))) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type))]
        
        wal_pattern_encrypt_attack_sub_behavior = encrypt_copy_or_encrypt_decrpyt_or_encrpyt_encrpyt_sub_dataframe.sort_values(by='SYSTEM_TimeCreated', ignore_index=True)
        #wal_pattern_encrypt_attack_sub_behavior_without_duplicates = wal_pattern_encrypt_attack_sub_behavior.drop_duplicates(ignore_index=True)

        security_event_seuqence_to_check = wal_pattern_encrypt_attack_sub_behavior[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_encrypt_attack_sub_behavior[['EVENTDATA_AccessList']].values.flatten().tolist()

        complete_windows_security_log_event_sequence_to_expect = []
        complete_security_access_type_sequence_to_expect = []

        for itr in range(number_of_files_to_copy_or_encrypt_or_decrypt):
            # update windows security log events sequence
            complete_windows_security_log_event_sequence_to_expect = complete_windows_security_log_event_sequence_to_expect + [single_windows_security_log_event_sequence_to_expect[0]]
            # update windows security access type seuqence
            complete_security_access_type_sequence_to_expect = complete_security_access_type_sequence_to_expect + [single_security_access_type_sequence_to_expect[0]]
        
        if((len(security_event_seuqence_to_check) == len(complete_windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check) == len(complete_security_access_type_sequence_to_expect))):
            for idx, event_row in enumerate(complete_windows_security_log_event_sequence_to_expect):
                # explicitly check every element because object file names vary while copying different files
                if((complete_windows_security_log_event_sequence_to_expect[idx][0] != security_event_seuqence_to_check[idx][0]) or (complete_windows_security_log_event_sequence_to_expect[idx][1] != security_event_seuqence_to_check[idx][1]) or (not(complete_windows_security_log_event_sequence_to_expect[idx][2] in security_event_seuqence_to_check[idx][2])) or (not('.dat' in security_event_seuqence_to_check[idx][2]))):
                    quality_evaluation_results[0] = False
            # explicitly check because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(complete_security_access_type_sequence_to_expect):
                if(not(complete_security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        # if wal_dataframe is empty 
        wal_pattern_encrypt_attack_sub_behavior = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        description_expected_entries = "out of " + str(number_of_files_to_copy_or_encrypt_or_decrypt) + " entry/entries expected"
        if(wal_pattern_encrypt_attack_sub_behavior.empty):
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'encrypt subattack - count of filtered row entries' , 0, description_expected_entries)
            # final log entry to sum up results
            logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "empty dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time:', end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'encrypt subattack - count of filtered row entries' , encrypt_copy_or_encrypt_decrpyt_or_encrpyt_encrpyt_sub_dataframe.shape[0], description_expected_entries)
            
            # final log entry to sum up results
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt.strftime("%d/%m/%Y %H:%M:%S:%f"))
          
    return quality_evaluation_results

def quality_check_encrypt_delete(wal_dataframe:pd.DataFrame, start_time_encrypt_delete:datetime.datetime, end_time_encrypt_delete:datetime.datetime,
                           encrypt_delete_object_name:str='C:\\localstorage\\sim23_encrypt_dest', encrypt_delete_access_type:str='%%1537', encrypt_delete_process_name:str='C:\\Windows\\System32\\cmd.exe', encrypt_delete_event_id:str='4663',
                           log_wal_quality_evaluation:bool=True, sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None):
    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for encrypt delete behavior sim23

    Args:
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_time_encrypt_delete (datetime.datetime): start timestamp of sim23 behavior of interest
        end_time_encrypt_delete (datetime.datetime): end timestamp of sim23 behavior of interest
        encrypt_delete_object_name (str): name of object being accessed during encrypt delete files (.dat-files in folder) step of encrypt delete behavior (all files are deleted over cmd by one command execution)
        encrypt_delete_access_type (str): access type included in windows security event during encrypt delete files (.dat-files in folder) step of encrypt delete behavior (all files are deleted over cmd by one command execution)
        encrypt_delete_process_name (str): program executable that accessed the object during encrypt delete files (.dat-files in folder) step of encrypt delete behavior (all files are deleted over cmd by one command execution)
        encrypt_delete_event_id (str): windows security event id of interest during encrypt delete files (.dat-files in folder) step of encrypt delete behavior (all files are deleted over cmd by one command execution)
        log_wal_quality_evaluation (bool, optional): log quality check results in log file if True, else no logging will be applied
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)

    Returns:
        list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """
    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_encrypt_delete started')

    
    # to keep it similiar both quality check values will be used at this point in code as well
    # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events
    quality_evaluation_results = [True, True]

    single_windows_security_log_event_sequence_to_expect = [[encrypt_delete_process_name, encrypt_delete_event_id, encrypt_delete_object_name]]
    single_security_access_type_sequence_to_expect = [encrypt_delete_access_type]

    if(not wal_dataframe.empty):
        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_time_encrypt_delete) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_time_encrypt_delete)].copy()

        encrypt_delete_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == encrypt_delete_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == encrypt_delete_event_id) & \
                                                (dataframe_copy['EVENTDATA_ObjectName'] == encrypt_delete_object_name) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(encrypt_delete_access_type))]
        
        wal_pattern_encrypt_attack_sub_behavior = encrypt_delete_sub_dataframe.sort_values(by='SYSTEM_TimeCreated', ignore_index=True)
        #wal_pattern_encrypt_attack_sub_behavior_without_duplicates = wal_pattern_encrypt_attack_sub_behavior.drop_duplicates(ignore_index=True)

        security_event_seuqence_to_check = wal_pattern_encrypt_attack_sub_behavior[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_encrypt_attack_sub_behavior[['EVENTDATA_AccessList']].values.flatten().tolist()
        
        if((len(security_event_seuqence_to_check) == len(single_windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check) == len(single_security_access_type_sequence_to_expect))):
            for idx, event_row in enumerate(single_windows_security_log_event_sequence_to_expect):
                # explicitly check every element because object file names vary while copying different files
                if((single_windows_security_log_event_sequence_to_expect[idx][0] != security_event_seuqence_to_check[idx][0]) or (single_windows_security_log_event_sequence_to_expect[idx][1] != security_event_seuqence_to_check[idx][1]) or (not(single_windows_security_log_event_sequence_to_expect[idx][2] in security_event_seuqence_to_check[idx][2]))):
                    quality_evaluation_results[0] = False
            # explicitly check because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(single_security_access_type_sequence_to_expect):
                if(not(single_security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        wal_pattern_encrypt_attack_sub_behavior = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        if(not wal_pattern_encrypt_attack_sub_behavior.empty):
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'encrypt delete count of filtered row entries' , encrypt_delete_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            
            # final log entry to sum up results
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_encrypt_attack_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
             logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'encrypt delete count of filtered row entries' , 0, "out of 1 entry/entries expected")
             # final log entry to sum up results
             logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "empty dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_encrypt_delete.strftime("%d/%m/%Y %H:%M:%S:%f"))

    return quality_evaluation_results

def quality_check_mailing_with_attachment_and_save(wal_dataframe:pd.DataFrame, start_time_mailing:datetime.datetime, end_time_mailing:datetime.datetime, mailing_with_attachment_and_save_process_name:str ='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\python\\3.11.3\\python.exe',
                                                   mailing_with_attachment_and_save_event_id:str='4663', mailing_with_attachment_and_save_object_name:str= 'C:\\localstorage\\attachment', mailing_with_attachment_and_save_access_type:str='%%4417', log_wal_quality_evaluation:bool=True,
                                                   sim23_log_behavior_label:str="UNDEFINED", logging_file_path:pathlib.Path=None, sim_user_of_interest:str=None):
    """check if windows security events occur in specific security event order (based on implemented simulation behavior) & the count of specific events machtes the sim23 log timestamps => for encrypt delete behavior sim23

    Args:
        wal_dataframe (pd.DataFrame): dataframe which contains windows security events
        start_time_mailing (datetime.datetime): start timestamp of sim23 behavior of interest
        end_time_mailing (datetime.datetime): end timestamp of sim23 behavior of interest
        mailing_with_attachment_and_save_process_name (_type_, optional): program executable that access the object while downloading the .dat file in mail attachment (.dat-files in folder). Defaults to 'C:\\Users\\SimUser001\\scoop\\apps\\python\\3.11.3\\python.exe'.
        mailing_with_attachment_and_save_event_id (str, optional): windows security event id of interest during mailing with saving attachment file localy. Defaults to '4663'.
        mailing_with_attachment_and_save_object_name (_type_, optional):  name of object being created .mailing behavior. Defaults to 'C:\\localstorage\\attachment'.
        mailing_with_attachment_and_save_access_type (str, optional): access type included in windows security event during mailing and saving file (.dat-file). Defaults to '%%4417'.
        log_wal_quality_evaluation (bool, optional): log quality check results in log file if True, else no logging will be applied. Defaults to True.
        sim23_log_behavior_label (str): name of the sim23 log behavior which is quality checked
        logging_file_path (pathlib.Path): path to log the quality evaluation results. Defaults to None (take path out of config file in same folder)
        sim_user_of_interest (str): name of simulation user which is focused in quality check

    Returns:
        list: list: returns list with two bool values -> first value is true if windows security events occur in pre-defined order and second value is true if windows security events occur in pre-defined count, otherwise return false for specific values
    """
    if(log_wal_quality_evaluation):
        if(logging_file_path == None):
            logging.basicConfig(filename=pathlib.Path(load_config_asset("LOGGING", "system_path_to_write_logs")), level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        else:
            logging.basicConfig(filename=logging_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt="%d/%m/%Y %H:%M:%S")
        logging.info('|%s|%s', sim23_log_behavior_label, 'method wal_quality_evaluation.quality_check_mailing_with_attachment_and_save started')

    mailing_with_attachment_and_save_process_name = mailing_with_attachment_and_save_process_name.replace(SIM_USER_DUMMY_TAG, sim_user_of_interest)
    # to keep it similiar both quality check values will be used at this point in code as well
    # first value refers to pre-defined security event order, second value referes to the expected amount of specific security events
    quality_evaluation_results = [True, True]

    single_windows_security_log_event_sequence_to_expect = [[mailing_with_attachment_and_save_process_name, mailing_with_attachment_and_save_event_id, mailing_with_attachment_and_save_object_name]]
    single_security_access_type_sequence_to_expect = [mailing_with_attachment_and_save_access_type]

    if(not wal_dataframe.empty):

        dataframe_copy = wal_dataframe[(wal_dataframe['SYSTEM_TimeCreated'] >= start_time_mailing) & (wal_dataframe['SYSTEM_TimeCreated'] <= end_time_mailing)].copy()

        mailing_with_attachment_sub_dataframe = dataframe_copy[(dataframe_copy['EVENTDATA_ProcessName'] == mailing_with_attachment_and_save_process_name) & \
                                                (dataframe_copy['SYSTEM_EventID'] == mailing_with_attachment_and_save_event_id) & \
                                                ((dataframe_copy['EVENTDATA_ObjectName'].str.contains(mailing_with_attachment_and_save_object_name, regex=False)) & (dataframe_copy['EVENTDATA_ObjectName'].str.contains('.dat'))) & \
                                                (dataframe_copy['EVENTDATA_AccessList'].str.contains(mailing_with_attachment_and_save_access_type))]
        
        wal_pattern_mailing_with_attachment_sub_behavior = mailing_with_attachment_sub_dataframe.sort_values(by='SYSTEM_TimeCreated', ignore_index=True)

        security_event_seuqence_to_check = wal_pattern_mailing_with_attachment_sub_behavior[['EVENTDATA_ProcessName', 'SYSTEM_EventID', 'EVENTDATA_ObjectName']].values.tolist()
        security_access_type_sequence_to_check = wal_pattern_mailing_with_attachment_sub_behavior[['EVENTDATA_AccessList']].values.flatten().tolist()

        if((len(security_event_seuqence_to_check) == len(single_windows_security_log_event_sequence_to_expect)) and (len(security_access_type_sequence_to_check) == len(single_security_access_type_sequence_to_expect))):
            for idx, event_row in enumerate(single_windows_security_log_event_sequence_to_expect):
                # explicitly check every element because object file names vary while copying different files
                if((single_windows_security_log_event_sequence_to_expect[idx][0] != security_event_seuqence_to_check[idx][0]) or (single_windows_security_log_event_sequence_to_expect[idx][1] != security_event_seuqence_to_check[idx][1]) or (not(single_windows_security_log_event_sequence_to_expect[idx][2] in security_event_seuqence_to_check[idx][2])) or (not('.dat' in security_event_seuqence_to_check[idx][2]))):
                    quality_evaluation_results[0] = False
            # explicitly check because security event can contain more than one specific access type in access list
            for idx, access_list_elemet in enumerate(single_security_access_type_sequence_to_expect):
                if(not(single_security_access_type_sequence_to_expect[idx] in security_access_type_sequence_to_check[idx])):
                    quality_evaluation_results[0] = False
        else:
            quality_evaluation_results = [False, False]
    else:
        wal_pattern_mailing_with_attachment_sub_behavior = wal_dataframe
        quality_evaluation_results = [False, False]

    if(log_wal_quality_evaluation):
        if(not wal_pattern_mailing_with_attachment_sub_behavior.empty):
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'mailing save attachment count of filtered row entries' , mailing_with_attachment_sub_dataframe.shape[0], "out of 1 entry/entries expected")
            
            # final log entry to sum up results
            if((quality_evaluation_results[0] == True) and (quality_evaluation_results[1] == True)):
                logging.info('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_mailing_with_attachment_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_mailing_with_attachment_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"))
            else:
                logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , str(wal_pattern_mailing_with_attachment_sub_behavior['SYSTEM_TimeCreated'].iloc[0]), 'last event timestamp of complete wal sequence' , str(wal_pattern_mailing_with_attachment_sub_behavior['SYSTEM_TimeCreated'].iloc[-1]), 'sim23 log start time', start_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"))
        else:
            logging.debug('|%s|%s|%s %s',  'detailed quality check info', 'mailing save attachment count of filtered row entries' , 0, "out of 1 entry/entries expected")
            # final log entry to sum up results
            logging.error('|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s|%s-%s', 'security event sequence order check was successful', str(quality_evaluation_results[0]), 'security event sequence occured in pre-defined count', str(quality_evaluation_results[1]), 'first event timestamp of complete wal sequence' , "empty dataframe", 'last event timestamp of complete wal sequence' , "empty dataframe", 'sim23 log start time', start_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"), 'sim23 log end time', end_time_mailing.strftime("%d/%m/%Y %H:%M:%S:%f"))

    return quality_evaluation_results

def wal_general_quality_check_handler_sim23_log_based(sim23_logs:list, audit_data:pd.DataFrame, logging_path:pathlib.Path=None, sim_user_of_interest:str=None, timezone:str=None):
    """automated quality evaluation processing based on collected windows audit log files (converted) & sim 23 logs for each iteration

    Args:
        sim23_logs (list): behavior description of cidds-framework behavior
        audit_data (pd.DataFrame): dataframe with windows audit log data to analyze
        logging_path (pathlib.Path): path to write the quality check logs
        sim_user_of_interest (str): simulation user which should be evaluated regarding  its behavior logs
        timezone (str): timezone of simulation recording (different for hardware and software simulation)

    Returns:
        int: returns the count of done quality checks for Windows security audit logs
    """
    # count of done quality checks initiated by the handler method
    done_quality_checks = 0
    if(sim23_logs):
        for idx, log_entry in enumerate(sim23_logs):
            data = audit_data[(audit_data['SYSTEM_TimeCreated'] >= log_entry[0]) & (audit_data['SYSTEM_TimeCreated'] <= log_entry[1])].copy()
            # if data is empty it will be logged while doing the quality checks
            if('encrypt' in log_entry[-1]):
                # differentiate between encrypt copy, encrypt, decrypt, delete attack steps
                if('copy' in log_entry[-1]):
                    quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name='C:\\localstorage\\sim23_encrypt_dest', encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type='%%4417', number_of_files_to_copy_or_encrypt_or_decrypt=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][1],wal_dataframe=data, start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[0], end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][0], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
                elif('decrypt' in log_entry[-1]):
                    quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name='C:\\localstorage\\sim23_encrypt_dest', encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type='%%4417', number_of_files_to_copy_or_encrypt_or_decrypt=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][1],wal_dataframe=data, start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[0], end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][0], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
                elif('delete' in log_entry[-1]):
                    quality_check_encrypt_delete(sim23_log_behavior_label= log_entry[-1], wal_dataframe=data, start_time_encrypt_delete=log_entry[0], end_time_encrypt_delete=log_entry[1], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
                elif('encrypt_encrypt' in log_entry[-1]):
                    quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_object_name='C:\\localstorage\\sim23_encrypt_dest', encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_access_type='%%4417', number_of_files_to_copy_or_encrypt_or_decrypt=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][1],wal_dataframe=data, start_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[0], end_time_quality_check_encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt=log_entry[1], encrypt_copy_or_encrypt_encrypt_or_encrypt_decrypt_process_name=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][0], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
            elif('mailing' in log_entry[-1]):
                # if attachment gets downloaded while simulating mailing behavior
                if('and_save'in log_entry[-1]):
                    quality_check_mailing_with_attachment_and_save(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], wal_dataframe=data, start_time_mailing=log_entry[0], end_time_mailing=log_entry[1], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
            elif('programming' in log_entry[-1]):
                if('java' in log_entry[-1]):
                    if((sim_user_of_interest=="SimUser003") and (timezone == "CEST")):
                        # in recording setup SimUser003 has a different java version than the rest of the simulation users by default -> bug in simulation environment
                        quality_check_programming_behavior_java(execute_sim23_class_file_object_name='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.2-13\\bin\\server\\jvm.dll', execute_sim23_class_file_process_name='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.2-13\\bin\\java.exe', compile_create_class_file_process_name='C:\\Users\\'+SIM_USER_DUMMY_TAG+'\\scoop\\apps\\openjdk\\21.0.2-13\\bin\\javac.exe', sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], wal_dataframe=data, start_timestamp_programming_behavior=log_entry[0], end_timestamp_programming_behavior=log_entry[1], logging_file_path=logging_path)
                    else:
                        quality_check_programming_behavior_java(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], wal_dataframe=data, start_timestamp_programming_behavior=log_entry[0], end_timestamp_programming_behavior=log_entry[1], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
                elif('python' in log_entry[-1]):
                    quality_check_programming_behavior_python(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], wal_dataframe=data, start_timestamp_programming_behavior=log_entry[0], end_timestamp_programming_behavior=log_entry[1], logging_file_path=logging_path)
                    # update count of done quality checks
                    done_quality_checks = done_quality_checks + 1
            elif('copy' in log_entry[-1]):
                quality_check_copy_local_to_local_and_net_to_local(sim_user_of_interest=sim_user_of_interest, sim23_log_behavior_label= log_entry[-1], complete_copy_behavior_object_name=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][0], number_of_files_to_copy=LABEL_WAL_FEATURE_MAPPING[log_entry[-1]][1], wal_dataframe=data, start_time_copy_behavior=log_entry[0], end_time_copy_behavior=log_entry[1], logging_file_path=logging_path)
                # update count of done quality checks
                done_quality_checks = done_quality_checks + 1

    return done_quality_checks

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