import os
import json

f = open('malware_APKs.txt', 'r')
data = json.load(f)
f.close()

print(len(data['AMD']))
print(len(data['Drebin']))