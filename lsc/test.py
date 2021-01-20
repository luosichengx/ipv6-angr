import os
exlude_list = []
exlude_list.extend(map(lambda x: x.split(".")[0], os.listdir("/home/lsc/data/log/log")))
for root, dir, files in os.walk("/home/lsc/data/log/con"):
    files = list(filter(lambda x:x.startswith("expand"), files))
    files.sort(key=lambda x:(len(x), x))
    for file in files:
        print(file)