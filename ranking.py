import json


# define path of json files
permission_path = 'data/permissions.json'
api_path = 'data/apis.json'

# read data from json
f = open(permission_path, 'r')
permissions = json.load(f)
f.close()

f = open(api_path, 'r')
apis = json.load(f)
f.close()

# Permissions sorted dict with descending order
# re-create the dict with count 
result = {}
for i, (k, v) in enumerate(permissions.items()):
    if k not in result.keys():
        result[k] = {}
    num = 0
    for k1, v1 in v.items():
        result[k][k1] = v1
        for value in v1:
            num += 1
    result[k]['count'] = num    # added count keyword 

# sort dict with descending order of count keyword
items = result.items()
sorted_items = sorted(items, key=lambda key_value: key_value[1]['count'], reverse=True)

# convert sorted array to dict
ans = {}
for (k, v) in sorted_items:
    del v['count']
    ans[k] = v

# write to json
f = open('data/total_permissions.json', 'w')
json.dump(ans, f, indent=4)
f.close()

# APIs sorted dict with descending order
result = {}
for i, (k , v) in enumerate(apis.items()):
    if k not in result.keys():
        result[k] = {}
    num = 0
    for k1, v1 in v.items():
        result[k][k1] = v1
        for value in v1:
            num += 1
    result[k]['count'] = num

items = result.items()
sorted_items = sorted(items, key=lambda key_value: key_value[1]['count'], reverse=True)

ans = {}
for (k , v) in sorted_items:
    del v['count']
    ans[k] = v

f = open('data/total_apis.json', 'w')
json.dump(ans, f, indent=4)
f.close()