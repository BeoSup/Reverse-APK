import os
import json

import pandas as pd
from os.path import join as join_dir

permissions_path = 'data/total_permissions.json'
apis_path = 'data/total_apis.json'
files_path = 'data/files.csv'

f = open(permissions_path, 'r')
permissions = json.load(f)
f.close()

f = open(apis_path, 'r')
apis = json.load(f)
f.close()

f = open(files_path, 'r')
apk_names = json.load(f)
f.close()

data = []

for iaf, (kaf , vaf) in enumerate(apk_names.items()):
    for id, value in enumerate(vaf):
        data.append({
            'filename': value,
            'label': kaf,
        })
        for ip, (kp, vp) in enumerate(permissions.items()):
            data[id][kp] = 0
            for k2, v2 in vp.items():
                if k2 == kaf:
                    for val in v2:
                        if val == value:
                            data[id][kp] = 1
        for ia, (ka, va) in enumerate(apis.items()):
            data[id][ka] = 0
            for k1, v1 in va.items():
                if k1 == kaf:
                    for val in v1:
                        if val == value:
                            data[id][ka] = 1

df = pd.DataFrame(data)
df.to_csv('data/total.csv')