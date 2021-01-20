import logging
import itertools
import claripy
import angr
import psutil
import os
import gc
from memory_protection import *
# import tracemalloc
import sys

logger_angr = logging.getLogger('angr')
logger_angr.setLevel(logging.CRITICAL)
sym_argv = claripy.BVS('sym_argv', 8 * 8)
p = angr.Project("/home/lsc/gnucore/pathchk", load_options={"auto_load_libs": False})
state = p.factory.entry_state(args=[p.filename, sym_argv])
pg = p.factory.simgr(state)

# pg.use_technique(
#     angr.exploration_techniques.Spiller(min=10, max=150, src_stash="deferred", staging_max=150, staging_min=0))
# pg.use_technique(angr.exploration_techniques.DFS())
# print("spiller")
# pg.use_technique(angr.exploration_techniques.Spiller(min=10,max=30, staging_stash="deferred", staging_max=200))
pg.use_technique(bfs_memory_protection())
# tracemalloc.start()
def my_split(state_list):
    # jump_list = []
    # stay_list = []
    # move_list = []
    # for i in state_list[150:]:
    #     del i.solver
    #     del i.memory
    #     try:
    #         i.memory.mem._pages.clear()
    #     except:
    #         pass
    #     if i.addr not in jump_list:
    #         jump_list.append(i.addr)
    #         stay_list.append(i)
    #     else:
    #         move_list.append(i)
    # return stay_list, move_list
    return state_list[:150], state_list[150:]


def my_step_func(lpg):
    if len(lpg.active) > 1:
        print(lpg)
    # try:
    #     for s in lpg.active:
    #         s.downsize()
    #     for s in lpg.deadended:
    #         del s.solver
    #         del s.memory
    #         s.downsize()
    #     for s in lpg.deferred:
    #         s.downsize()
    # except:
    #     pass
    lpg.drop(stash="deadended")

    # if len(lpg.stashes['deferred']) > 200:
        # snapshot = tracemalloc.take_snapshot()
        # top_stats = snapshot.statistics('lineno')
        #
        # for stat in top_stats[:3]:
        #     print(stat)

        # print(lpg)

        # del lpg._stashes['active'][30:]
        # gc.collect()
        # a = lpg._stashes['stashed'][0]
        # gc.collect()
        # lpg.drop(stash="stashed")
    return lpg


for _ in (itertools.count()):
    if not pg.complete() and pg._stashes['active']:
        pg.run(n=1, step_func=my_step_func)
        # if len(pg._stashes['active']) > 20:
        #     pg.merge(stash='active')
        print(pg)
        # m = psutil.Process(os.getpid()).memory_percent()
        # print(m,_)
    else:
        break