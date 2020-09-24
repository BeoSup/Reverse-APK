import os
import json

# BASE = os.path.realpath('/home/beo/Documents/malware_analysis/malicious_code')
BASE = os.path.realpath('/home/beo/Downloads/Test/Drebin')

labels = []
permissions = {}
apis = {}
errors = []

if not os.path.exists('data'):
    os.makedirs('data')

for feature in os.listdir(BASE):
    labels.append(feature)
    output_folder = os.path.join(BASE, feature, 'output')
    for file in os.listdir(output_folder):
        print(os.path.join(output_folder, file))
        f = open(os.path.join(output_folder, file), 'r')
        if file.endswith('-analysis.json'):
            data = json.load(f)
        elif file == 'errors.txt':
            for error_apk in f.readlines():
                errors.append((output_folder.replace('/home/beo/Documents/malware_analysis/malicious_code', '').replace('output', '') + error_apk).replace('\n', ''))
        f.close()
        for permission in data['Static_analysis']['Permissions']:
            if permission not in permissions.keys():
                permissions[permission] = {}
            if feature not in permissions[permission]:
                permissions[permission][feature] = [data['Pre_static_analysis']['Filename']]
            else:
                permissions[permission][feature].append(data['Pre_static_analysis']['Filename'])
        for api in data['Static_analysis']['API calls']:
            if api not in apis.keys():
                apis[api] = {}
            if feature not in apis[api].keys():
                apis[api][feature] = [data['Pre_static_analysis']['Filename']]
            else:
                apis[api][feature].append(data['Pre_static_analysis']['Filename'])

f = open('data/total_permissions.json', 'w+')
json.dump(permissions, f, indent=4)
f.close()

f = open('data/total_apis.json', 'w+')
json.dump(apis, f, indent=4)
f.close()

f = open('data/total_errors.txt', 'w+')
for error_apk in errors:
    f.write(error_apk + '\n')
f.close()