import argparse
import traceback

import os
import signal
from preprocessing.query_to_tree import Script_Info, query_tree
from z3 import Solver as z3Solver
from z3 import parse_smt2_string

parser = argparse.ArgumentParser()
parser.add_argument('--input', default='/home/lsc/smt-comp')
args = parser.parse_args()

error_count = 0
correct_count = 0
time_error = 0
error_count1 = 0
correct_count1 = 0
count = 0

def handler(signum, frame):
    signal.alarm(1)
    raise TimeoutError

# for dir in os.listdir(args.input):
for dir in ["QF_BV", "QF_LIA", "QF_LRA", "QF_NIA", "QF_RDL", "QF_UFBV"]:
# for dir in ["QF_UFBV"]:
    for root, dirs, files in os.walk(os.path.join(args.input, dir)):
        for file in files:
            if file.endswith(".txt"):
                continue
            # print(os.path.join(root, file))
            with open(os.path.join(root, file), "r") as f:
                data = f.read()
            script = Script_Info(data, False)
            try:
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(1)
                querytree = query_tree(script)
                querytree.script_to_feature()
                if len(querytree.feature_list):
                    correct_count += 1
                else:
                    error_count += 1
                signal.alarm(0)
            except TimeoutError:
                signal.alarm(0)
                time_error += 1
                error_count += 1
            except Exception as e:
                signal.alarm(0)
                # traceback.print_exc()
                error_count += 1
            # try:
            #     script = parse_smt2_string(data)
            #     z3s = z3Solver(ctx=script.ctx)
            #     z3s.from_string(data)
            #     correct_count += 1
            # except:
            #     error_count += 1
            if error_count ==5 or correct_count == 5:
                print("path_name:"+root)
                print("error_count:" + str(error_count))
                print("correct_count:" + str(correct_count))
                print("time_error:" + str(time_error))
                if error_count > correct_count:
                    error_count1 += 1
                else:
                    correct_count1 += 1
                error_count = 0
                correct_count = 0
                time_error = 0
                break
        if error_count1 ==2 or correct_count1 ==2:
            print("----------------------------")
            print("path_name:" + dir)
            print("error_count:" + str(error_count1))
            print("correct_count:" + str(correct_count1))
            print("----------------------------")
            # if error_count1 ==1:
            #     exit(1)
            error_count1 = 0
            correct_count1 = 0
            break