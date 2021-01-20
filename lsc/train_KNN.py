import argparse
import collections

import json
import os
import time
import random
import numpy as np
np.set_printoptions(suppress=True)

from claripy.backends.dgl_treelstm.KNN import KNN
from claripy.backends.preprocessing import query_feature_Dataset,op
import warnings
import time

warnings.filterwarnings('ignore')

def main(args):
    train_file = os.path.join("/home/lsc/miniconda3/envs/angr-timer/lib/python3.7/site-packages/claripy/backends/KNN_training_data/gnucore.json")
    with open(train_file, "r") as f:
        train_dataset = json.load(f)

    # knn classifier
    test_dataset = None
    total_num = 0
    incremental_total_result = []
    sklearn_total_result = []
    truth = []
    s = time.time()
    filename = "tr"
    incremental_predict = simple_KNN(args, train_dataset, filename)
    incremental_total_result.extend(incremental_predict)
    e = time.time()
    print("time", e - s, "data number", len(truth))
    print("total result:")

def simple_KNN(args, train_dataset, filename):
    clf = KNN(k=3)
    dataset = query_feature_Dataset(feature_number_limit=2)
    y_train = np.array([1 if i > args.time_limit_setting else 0 for i in train_dataset["adjust"]])
    x_train = np.array(train_dataset["x"])
    clf.fit(x_train, y_train)
    clf.filename = np.array(train_dataset["filename"])
    clf.remove_test(filename)
    y_test = []
    y_test_pred = []
    str_list = []
    for root, dir, files in os.walk("/home/lsc/data/log/con"):
        files.sort(key=lambda x:(len(x), x))
        for file in files:
            if file.startswith(filename):
                with open(os.path.join(root,file), "r") as f:
                    data = f.read()
                    data = json.loads(data)
                    x_test = data["script"]
                    str_list.append(x_test)
                    y = 1 if data["time"] > args.time_limit_setting else 0
                    data = dataset.generate_feature_dataset([x_test], time_selection="z3")
                    x_test = np.array(data[-1].feature).reshape(-1, 300)
                    y_pred = clf.predict(x_test)
                    if not y_pred:
                        clf.incremental(x_test, y)
                        y_test.append(y)
                        y_test_pred.append(y_pred)
                    print(y_pred)
    acc, pre, rec, fls = clf.score(y_test, y_test_pred)
    print('incremental test accuracy: {:.3}, precision: {:.3}, recall: {:.3}, f1 score: {:.3}'.format(acc, pre, rec, fls))
    return y_test_pred


def parse_arg():
    # global args
    parser = argparse.ArgumentParser()
    parser.add_argument('--num_classes', type=float, default=2)
    parser.add_argument('--data_source', default='gnucore/fv2')
    parser.add_argument('--input', default='gnucore/training')
    parser.add_argument('--single_test', action='store_true')
    parser.add_argument('--time_selection', default='origin')
    parser.add_argument('--augment', action='store_true')
    parser.add_argument('--augment_path', default='data/gnucore/augment/crosscombine')
    parser.add_argument('--cross_project', action='store_true')
    parser.add_argument('--eva_input', default='busybox/fv2')
    parser.add_argument('--time_limit_setting', type=int, default=300)
    parser.add_argument('--model_selection', default="all")
    args = parser.parse_args()
    print(args)
    return args


if __name__ == '__main__':
    args = parse_arg()
    main(args)