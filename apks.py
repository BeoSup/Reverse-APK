import os
import json

BASE = '/home/beo/Documents/malware_analysis/malicious_code'

outf = 'malware_APKs.txt'
AMD, drebin, errors = [], [], []

count = 0
for stamp in os.listdir(BASE):
    if stamp == 'AMD':
        for label in os.listdir(os.path.join(BASE, stamp)):
            path = os.path.join(BASE, stamp, label, 'output')
            for file in os.listdir(path):
                if file.endswith('-analysis.json'):
                    f = open(os.path.join(path, file), 'r')
                    data = json.load(f)
                    f.close()
                    if not data['Static_analysis']['Permissions'] or not data['Static_analysis']['API calls']:
                        continue
                    else:
                        AMD.append(file.replace('-analysis.json', '.apk'))
    elif stamp == 'Drebin':
        for label in os.listdir(os.path.join(BASE, stamp)):
            if label == 'feature_vectors':
                continue
            else:
                path = os.path.join(BASE, stamp, label, 'output')
                for file in os.listdir(path):
                    if file.endswith('-analysis.json'):
                        f = open(os.path.join(path, file), 'r')
                        data = json.load(f)
                        f.close()
                        if not data['Static_analysis']['Permissions'] or not data['Static_analysis']['API calls']:
                            continue
                        else:
                            drebin.append(file.replace('-analysis.json', '.apk'))

apks = {
    'AMD': AMD,
    'Drebin': drebin
}

print('Number os AMD files: {}'.format(len(AMD)))
print('Number drebin files: {}'.format(len(drebin)))

f = open(outf, 'w')
json.dump(apks, f, indent=4)
f.close()