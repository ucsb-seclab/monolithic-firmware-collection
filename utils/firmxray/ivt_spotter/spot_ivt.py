

import angr
import argparse
import logging
import os
import re 
import string
import shutil
import sys
import struct
sys.setrecursionlimit(10**9) 

from datetime import date, datetime
from cle.backends import NamedRegion

l = logging.getLogger("angr.spot_ivt")
l.setLevel(logging.DEBUG)


ll = logging.getLogger("angr.analyses.cfg.cfg_fast")
ll.setLevel(logging.CRITICAL)
lll = logging.getLogger("angr.analyses.cfg.cfg_base")
lll.setLevel(logging.CRITICAL)

def auto_int(x):
    return int(x, 0)

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("binary")
    opts = o.parse_args()
    return opts

def ExtractIVTAddresses(p, cfg, offset_ivt):
    
    ivt_abs = set()

    blank_state = p.factory.blank_state()
    blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    
    j = 0
    stack_pointer = blank_state.memory.load(offset_ivt + j, 4, endness="Iend_LE")
    j += 4 
    entry_point = blank_state.memory.load(offset_ivt + j, 4, endness="Iend_LE")
    j += 4 
    
    while True:
        p = blank_state.solver.eval(blank_state.memory.load(offset_ivt + j, 4, endness="Iend_LE"))
        # An heuristic to detect the end of the IVT table (can be imprecise).
        if p == 0x00000000 or p == 0xffffffff or p == 0x00ffffff or p == 0x0000ffff or p == 0x000000ff:
            break
        else:
            ivt_abs.add(p)
            j += 4
    
    return ivt_abs 


MIN_FUNCTION_TO_BE_ENTRY_POINT = 2 
DELTA_MAX_BETWEEN_IRQ_HANDLERS_ADDR = 0x1000
MAX_DWORDS_AFTER_EP = 4
SKIP_DWORDS_FROM_IVT_OFFSET = 8 

if __name__ == "__main__":
    opts = parse_opts()
    blob_path = opts.binary


    p = angr.Project(blob_path, main_opts={'base_addr': 0x0, 
                                       'arch': "ARMCortexM", 
                                       'entry_point': 0x0, 
                                       'backend': 'blob'})

    #cfg = p.analyses.CFG(resolve_indirect_jumps=True, 
    #                     cross_references=True, 
    #                     function_prologues=True, # force detection using ARM's function prologues.
    #                     show_progressbar=False,
    #                     normalize=True, symbols=True, start_at_entry=True)


    blob_stream = open(blob_path, "rb")
    
    possible_IVT_offsets = []
    
    min_arm_sp = 0x1FFF0000
    max_arm_sp = 0x20100000

    min_addr_blob = p.loader.main_object.min_addr
    max_addr_blob = p.loader.main_object.max_addr


    blob_stream.seek(0)
    
    entry_num_funcs = {}

    while True:
        try:
            if blob_stream.tell() >= max_addr_blob or blob_stream.tell() + 0x4 >= max_addr_blob:
                break
            #print("Reading at {}".format(hex(blob_stream.tell())))
            maybe_sp = blob_stream.read(4)
            maybe_le_sp = struct.unpack('<I', maybe_sp)[0]
            if maybe_le_sp >= min_arm_sp and maybe_le_sp <= max_arm_sp:
                #print("Found {} at {}".format(hex(maybe_le_sp), hex(blob_stream.tell()-0x4)))
                maybe_ep = blob_stream.read(4)
                maybe_le_ep = struct.unpack('<I', maybe_ep)[0]
                if maybe_le_ep >= min_addr_blob and maybe_le_ep <= max_addr_blob:
                    ivt_location = blob_stream.tell()- 0x8
                    p.entry_point = maybe_le_ep
                    p.entry = maybe_le_ep

                    cfg = p.analyses.CFG(resolve_indirect_jumps=False, 
                                        cross_references=False, 
                                        force_complete_scan=False,
                                        function_prologues=False,
                                        show_progressbar=False,
                                        normalize=True, symbols=True, start_at_entry=True)
                    
                    if len(p.kb.functions) > MIN_FUNCTION_TO_BE_ENTRY_POINT:
                        entry_num_funcs[ivt_location] = len(p.kb.functions)
                        #print("Possible IVT Location at {}".format(hex(ivt_location)))
                        possible_IVT_offsets.append(ivt_location)
                else:
                    # Move back and consider the next DWORD as possible SP
                    blob_stream.seek(-4)

        except Exception as e:
            continue
    
    new_possible_IVT_offsets = []
    delta_max = DELTA_MAX_BETWEEN_IRQ_HANDLERS_ADDR

    for o in possible_IVT_offsets:
        dwords_dumped = []
        blob_stream.seek(0)
        blob_stream.seek(o + SKIP_DWORDS_FROM_IVT_OFFSET) # skip stack pointer and entry point

        # read 4 dwords 
        for x in range(0,MAX_DWORDS_AFTER_EP):
            new_dword = blob_stream.read(4)
            try:
                new_dword = struct.unpack('<I', new_dword)[0]
            except Exception:
                break
            dwords_dumped.append(new_dword)

        is_ivt = True
        for i in range(0, len(dwords_dumped)-1):
            dword = dwords_dumped[i]
            dword_next = dwords_dumped[i+1]
            if abs(dword_next - dword) > delta_max:
                # Dwords are too further between them, probably not the IVT table.
                is_ivt = False
                break
        if is_ivt:
            new_possible_IVT_offsets.append(o)

    print("IVT TABLE CANDIDATES")
    for o in new_possible_IVT_offsets:
        print("Candidate {} | Num. Funcs. {}".format(hex(o), entry_num_funcs[o]))
