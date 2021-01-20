import json

import argparse

import configparser
import logging
import os
import platform
import traceback

import angr
import claripy
import time

from z3 import Solver as z3Solver
from z3 import parse_smt2_string

from memory_protection import bfs_memory_protection
import multiprocessing as mp

basedir = os.path.dirname(os.path.abspath(__file__))
cf = configparser.ConfigParser()
cf.read(basedir + "/config.ini")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(message)s")
fh = logging.FileHandler("origin.log", mode='w')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)
logger1 = logging.getLogger("angr")
logger1.setLevel(logging.CRITICAL)
logger1 = logging.getLogger("cle")
logger1.setLevel(logging.CRITICAL)


def run_symexe(args, bin_path):
    input_length = args.length

    if input_length is None:
        input_length = cf.getint("Symvar", "length")

    sym_argv = claripy.BVS('sym_argv', input_length * 8)
    sym_argv2 = claripy.BVS('sym_argv2', 2 * 8)
    sym_argv3 = claripy.BVS('sym_argv3', 2 * 8)
    sym_argc = claripy.BVS('sym_argc', 1 * 8)
    try:
        p = angr.Project(bin_path, load_options={"auto_load_libs": False})
    except:
        return
    main_obj = p.loader.main_object.get_symbol('main')
    state = p.factory.full_init_state(argc=sym_argc, args=[p.filename, sym_argv, sym_argv2, sym_argv3])
    pg = p.factory.simgr(state, auto_drop={"unsat", "error","spinning"})

    pg.use_technique(bfs_memory_protection())
    start_time = time.time()
    filename = bin_path.split("/")[-1]
    fn_len = len(filename)
    while(True):
        if not pg.complete() and pg._stashes['active']:
            pg.run(n=1)
            if len(pg.active) > 30:
                for root, dirs, files in os.walk("/home/lsc/data/log/con"):
                    for file in files:
                        if filename == file[:fn_len] and file[fn_len].isdigit():
                            with open(os.path.join(root, file), "r") as f:
                                data = json.load(f)
                                t = data["predict_time"]
                                if t == 0.0:
                                    continue
                                data = data["script"]
                                try:
                                    script = parse_smt2_string(data)
                                    z3s = z3Solver(ctx=script.ctx)
                                    z3s.set('timeout', 300000)
                                    z3s.from_string(data)
                                except Exception as e:
                                    traceback.print_exc()
                                    return
                                s = time.time()
                                res = z3s.check()
                                e = time.time()
                                st = os.path.join(root, file) + ', solver: z3, result: ' + str(res) + ', time:' + str(e - s)
                                logger.info(st)
                print("finish", bin_path)
                break
            continue
        break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="directory of file")
    parser.add_argument("-c", "--constraints", help="Deprecated: Show generated model", action="store_true")
    parser.add_argument("-C", "--compile", type=int,
                        help="Deprecated: Compile from source, if C > 0, -O option will be used")
    parser.add_argument("-l", "--length", type=int, help="Stdin size")
    parser.add_argument("-r", "--run_program", help="Run program after analysis", action="store_true")
    parser.add_argument("-s", "--summary", type=int, help="Deprecated: Display summary information")
    parser.add_argument("-e", "--expected", type=int, help="Deprecated: Expected amount of results")
    parser.add_argument("-f", "--file_path", type=str, help="file name path")
    parser.add_argument("-t", "--time", help="without time constraint", action="store_false")
    parser.add_argument("-de", "--debug", help="Deprecated: ctrl+c to debug the progress", action="store_true")
    parser.add_argument("-fl", "--file_list", help="list of file name")
    args = parser.parse_args()

    # process the file under the directory with multiprocess
    if args.dir is not None:
        dirpath = args.dir
        count = 0
        pro_list = []
        filename_list = args.file_list
        pool = mp.Pool(processes=8, maxtasksperchild=1)
        for root, dirs, files in os.walk(dirpath):
            if filename_list is not None:
                files = filename_list.split(",")
            for file in files:
                bin_path = os.path.join(root, file)
                pool.apply_async(run_symexe, (args, bin_path))
        pool.close()
        pool.join()

    print("all program ran")
