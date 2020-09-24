import os
import json

BASE_DIR = os.path.realpath(os.path.join(os.getcwd(), '../../malware_analysis/malicious_code'))

def main():
    temp = {}
    for feature in os.listdir(BASE_DIR):
        temp[feature] = 0
        for path, dirs, files in os.walk(os.path.join(BASE_DIR, feature)):
            temp[feature] += len(files)

    temp = dict(sorted(temp.items()))
    f = open('labels_num.json', 'w')
    json.dump(temp, f)
    f.close()

if __name__ == '__main__':
    main()