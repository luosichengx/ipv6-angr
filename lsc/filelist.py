import argparse

import json
import os
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dir", help="directory of data")
args = parser.parse_args()

a = []
for root, dirs, files in os.walk(args.dir):
    print(files)
    # for file in files:
        # with open(os.path.join(root, file), "r") as f:
        #     data = f.read()
        #     data = json.loads(data)
        # a.append(data["filename"])
# a = list(set(a))
# a = [x.split("/")[-1] for x in a]
# print(a)
