import hashlib
import sys
import argparse
import collections
import os
import json
import csv

from tqdm import tqdm
from os.path import join as join_dir
from features_management import *
from androguard.core.bytecodes import apk
from collections import Counter, OrderedDict

# VARIABLES
API_PACKAGES_LIST = []
API_CLASSES_LIST = []
API_SYSTEM_COMMANDS = []
package_index_file = 'info/package_index.txt'
classes_index_file = 'info/class_index.txt'
system_commands_file = 'info/system_commands.txt'
config_file = 'config.json'
BASE = os.getcwd()
# DEST = os.path.realpath('/home/beo/Documents/malware_analysis/malicious_code')

def main():
    print('Reverse APK...')
    parser = argparse.ArgumentParser()

    # parser.add_argument('-s', '--single', help='Sigle File Analysis', required=False, default=False)
    parser.add_argument('-p', '--path', help='Path to folder contains APK files', required=True)

    if len(sys.argv) < 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    apks_directory = args.path

    option_reverse(apks_directory)

def option_reverse(apks_directory):
    source_directory = str(apks_directory)
    output_folder = join_dir(source_directory, 'output')
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Load Android API packages and classes
    global API_PACKAGES_LIST, API_CLASSES_LIST, API_SYSTEM_COMMANDS

    # READING PACKAGES, CLASSES AND SYSTEM COMMANDS
    package_file = load_file(str(package_index_file))
    API_PACKAGES_LIST = [x.strip() for x in package_file]

    class_file = load_file(str(classes_index_file))
    API_CLASSES_LIST = [x.strip() for x in class_file]

    system_command_file = load_file(str(system_commands_file))
    API_SYSTEM_COMMANDS = [x.strip() for x in system_command_file]


    # BUILDING LIST OF APKS
    apk_list = list_files(source_directory, '*.apk')
    print('[*] Number of APKs: ' + str(len(apk_list)))

    # ANALYSING APKS
    # database = OrderedDict()
    print('ANALYSING APKS ...')
    for analyze_apk in tqdm(apk_list):
        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = source_directory.split('/')[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(source_directory, ''))
        apk_filename = apk_filename.replace('//', '')

        apk_name_no_extensions = ''.join(apk_filename.split('/')[-1].split('.')[:-1])

        print('Analyze on APK: ' + str(apk_name_no_extensions))
        # if apk_name_no_extensions == '8d53bf7dcf073f263900f3f07f2e7ef6':
        #     continue

        # if os.path.isfile(join_dir(output_folder, apk_filename.split('/')[-1].replace('.apk', '-analysis.json'))):
        #     database[apk_filename.replace('.apk', '')] = json.load(open(join_dir(output_folder, apk_filename.split('/')[-1].replace('.apk', '-analysis.json'))))

        #     continue
        
        pre_statict_dict = OrderedDict()

        pre_statict_dict['Filename'] = apk_name_no_extensions + '.apk'

        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()
        hasher_sha1 = hashlib.sha1()
        with open(analyze_apk, 'rb') as afile:
            buf = afile.read()
            hasher_md5.update(buf)
            hasher_sha256.update(buf)
            hasher_sha1.update(buf)
    
        md5 = hasher_md5.hexdigest()
        sha256 = hasher_sha256.hexdigest()
        sha1 = hasher_sha1.hexdigest()

        pre_statict_dict['md5'] = md5
        pre_statict_dict['sha256'] = sha256
        pre_statict_dict['sha1'] = sha1

        pre_statict_dict['VT_positives'] = None

        errors_file = join_dir(output_folder, 'errors.txt')
        try:
            androguard_apk_object = apk.APK(analyze_apk)
        except Exception as e:
            print('ERROR in APK: ' + apk_name_no_extensions + ', e: ' + str(e))
            with open(errors_file, 'a+') as f:
                f.write(apk_name_no_extensions + ': ' + str(e) + '\n')
            # cleanup(analyze_apk)
            continue

        static_analysis_dict = OrderedDict()

        # Package name
        static_analysis_dict['Package name'] = androguard_apk_object.get_package()

        # Permissions
        static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()

        # # Opcodes
        # static_analysis_dict['Opcodes'] = opcodes_analysis(androguard_apk_object)

        # Activities
        try:
            list_activities = androguard_apk_object.get_activities()
        except UnicodeEncodeError:
            list_activities = []

        # Main Activity
        static_analysis_dict['Main activity'] = androguard_apk_object.get_main_activity()

        # Receivers
        try:
            list_receivers = androguard_apk_object.get_receivers()
        except UnicodeEncodeError:
            list_receivers = []

        # Services
        try:
            list_services = androguard_apk_object.get_services()
        except UnicodeEncodeError:
            list_services = []

        # API calls and strings
        try:
            list_smali_api_calls, list_smali_strings = read_strings_and_apicalls(analyze_apk, API_PACKAGES_LIST, API_CLASSES_LIST)
        except RecursionError as e:
            with open(errors_file, 'a+') as f:
                f.write(apk_name_no_extensions + ': ' + str(e) + '\n')
            continue

        list_smali_api_calls_keys = list_smali_api_calls.keys()
        for api_call in list_smali_api_calls_keys:
            new_api_call = '.'.join(api_call.split('.')[:-1])
            # print(new_api_call + ' - ' + api_call)
            if new_api_call in list_smali_api_calls.keys():
                list_smali_api_calls[new_api_call] += list_smali_api_calls[api_call]
            else:
                # list_smali_api_calls[new_api_call] = list_smali_api_calls[api_call]
                # del list_smali_api_calls[api_call]
                list_smali_api_calls[new_api_call] = list_smali_api_calls.pop(api_call)
        static_analysis_dict['API calls'] = list_smali_api_calls
        static_analysis_dict['Strings'] = Counter(filter(None, list_smali_strings))

        # API PACKAGES
        API_packages_dict = OrderedDict()
        android_list_packages_lengths = [len(x.split('.')) for x in API_PACKAGES_LIST]
        # android_list_packages_lenghts = [len(x.split(".")) for x in API_PACKAGES_LIST]

        list_api_calls_keys = list_smali_api_calls.keys()
        for api_call in list_api_calls_keys:
            score = 0
            package_chosen = None
            for i, package in enumerate(API_PACKAGES_LIST):
                len_package = android_list_packages_lengths[i]
                if api_call.startswith(package) and len_package > score:
                    score = len_package
                    package_chosen = package
            if package_chosen is not None:
                if not package_chosen in API_packages_dict.keys():
                    API_packages_dict[package_chosen] = list_smali_api_calls[api_call]
                else:
                    API_packages_dict[package_chosen] += list_smali_api_calls[api_call]

        static_analysis_dict['API packages'] = API_packages_dict

        # System commands
        list_system_commands = read_system_commands(list_smali_strings, API_SYSTEM_COMMANDS)
        static_analysis_dict['System commands'] = Counter(list_system_commands)

        # Intents
        try:
            static_analysis_dict['Intents'] = intents_analysis(join_dir(analyze_apk.replace('.apk', ''), 'AndroidManifest.xml'))
        except:
            static_analysis_dict['Intents'] = {'Failed to extract intents': 0}

        # Intents of activities
        intents_activities = OrderedDict()
        for activity in list_activities:
            intents_activities[activity] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''), 'AndroidManifest.xml'), activity, 'activity')

        static_analysis_dict['Activities'] = intents_activities

        # Intents of Services
        intents_services = OrderedDict()
        for service in list_services:
            intents_services[service] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''), 'AndroidManifest.xml'), service, 'service')

        static_analysis_dict['Services'] = intents_services
        
        # Intents of receivers
        intents_receivers = OrderedDict()
        for intent in list_receivers:
            intents_receivers[intent] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''), 'AndroidManifest.xml'), intent, 'receiver')
        
        static_analysis_dict['Receivers'] = intents_receivers

        cleanup(analyze_apk)

        apk_total_analysis = OrderedDict([  ('Pre_static_analysis', pre_statict_dict),
                                            ('Static_analysis', static_analysis_dict)])

        # database[apk_filename.replace('.apk', '')] = apk_total_analysis

        save_as_json(apk_total_analysis, output_name=join_dir(output_folder, apk_name_no_extensions + '-analysis.json'))

    print('Analysis process is completed successfully...')

if __name__ == '__main__':
    # for label in os.listdir(DEST):
    #     if label == 'Airpush':
    #         path = join_dir(DEST, label)
    #         for folder in os.listdir(path):
    #             option_reverse(join_dir(path, folder))
    #     else:
    #         option_reverse(join_dir(DEST, label))

    main()