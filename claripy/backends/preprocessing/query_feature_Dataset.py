from .feature_vectors import *
import signal
import json
import time
import os
import random
import gc

def handler(signum, frame):
    signal.alarm(1)
    raise TimeoutError

class query_feature_Dataset():
    def __init__(self, feature_number_limit=100, treeforassert=False):
        self.str_list = []
        self.script_list = []
        self.qt_list = []
        self.is_json = True
        self.filename_list = []
        self.treeforassert = treeforassert
        self.feature_number_limit = feature_number_limit
        self.klee = False
        self.selected_file = False

    def generate_feature_dataset(self, input, time_selection=None):
        self.str_list = []
        if isinstance(input, list):
            self.str_list = input
        elif isinstance(input, str) and '\n' in input:
            self.str_list = [input]
        else:
            self.load_from_directory(input)
        if not len(self.str_list):
            return
        self.judge_json(self.str_list[0])
        selected_filename = []
        for ind, string in enumerate(self.str_list):
            script = Script_Info(string, self.is_json)
            # try:
                # if script.solving_time_dic["z3"][0] < 0:
                #     continue
                # if not self.selected_file:
                #     if float(script.solving_time) < 20 and float(script.solving_time_dic["z3"][0]) < 10:
                #         if len(self.str_list) > 20000 and ind % 10 != 0:
                #             continue
                # selected_filename.append(self.filename_list[ind])
            # except:
            #     continue
            self.script_list.append(script)
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(1)
            try:
                fv = self.parse_data(script, time_selection)
                self.qt_list.append(fv)
            except TimeoutError:
                signal.alarm(0)
                print("preprocess over time", len(self.qt_list))
                continue
            except (KeyError,IndexError):
                continue
            finally:
                signal.alarm(0)
            if len(self.qt_list) % 500 == 0:
                print(len(self.qt_list))
                # break
        # if not self.selected_file:
        #     with open(os.path.dirname(input) + "/selected_file.txt", "w") as f:
        #         for i in selected_filename:
        #             f.write(i + "\n")
        return self.qt_list

    def parse_data(self, script, time_selection):
        featurevectors = feature_vectors(script, time_selection, self.feature_number_limit)
        featurevectors.script_to_feature()
        if self.feature_number_limit == 2:
            fv = FV2(featurevectors)
        else:
            fv = FV(featurevectors)
        return fv

    # only accept files with single script
    def load_from_directory(self, input):
        if not input or input == "":
            return
        if os.path.isdir(input):
            # try:
            #     with open(os.path.dirname(input) + "/selected_file.txt") as f:
            #         selected_file = f.read().split("\n")
            #     self.selected_file = True
            # except:
            #     selected_file = None
            selected_file = None
            for root, dirs, files in os.walk(input):
                files.sort(key=lambda x: (len(x), x))
                for file in files:
                    if selected_file and file not in selected_file:
                        continue
                    # if os.path.getsize(os.path.join(root, file)) > 512 * 1024:
                    #     continue
                    self.read_from_file(file, os.path.join(root, file))
                    # if len(self.str_list) == 500:
                    #     return
        elif os.path.exists(input):
            self.read_from_file(None, input)

    def read_from_file(self, file, input):
        with open(input) as f:
            # if os.path.getsize(input) > 512 * 1024 or "klee" in input:
            if "klee" in input and "single_test" not in input:
                next = False
                start = False
                script = ""
                while(True):
                    try:
                        text_line = f.readline()
                        if text_line == "":
                            break
                    except:
                        continue
                    if "(set-logic QF_AUFBV )" in text_line:
                        start = True
                    if start:
                        script = script + text_line
                    if next == True:
                        self.str_list.append(script)
                        self.filename_list.append(file)
                        start = False
                        next = False
                        script = ""
                        if len(self.str_list) % 200 == 0:
                            print(len(self.str_list))
                    if "(exit)" in text_line:
                        next = True
            else:
                data = f.read()
                if data != "":
                    self.str_list.append(data)
                    self.filename_list.append(file)
                else:
                    data = ""


    def judge_json(self, data):
        try:
            json.loads(data)
            self.is_json = True
        except:
            pass

    def split_with_filename(self, test_filename=None):
        if not test_filename:
            random.shuffle(b)
            test_filename = b[:10]
        train_dataset = []
        test_dataset = []
        trt = 0
        tet = 0
        for qt in self.qt_list:
            if qt.filename in test_filename:
                test_dataset.append(qt)
                if qt.gettime() >= 300:
                    tet += 1
            else:
                train_dataset.append(qt)
                if qt.gettime() >= 300:
                    trt += 1
        return train_dataset,test_dataset

