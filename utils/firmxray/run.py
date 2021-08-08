'''
What: 
=====
This script re-implements the base-address detection
technique presented in the paper FirmXRay (http://web.cse.ohio-state.edu/~wen.423/papers/ccs20_FirmXRay).
I believe using angr and Python offeres a more friendly environment rather than using 
Java and the Ghidra API (DISCLAIMER: personal opinion).

Usage:
=====
`
> cd utils/
> python -m firmxray.run --ram 0x1fff0000 0x30000000 --cortexm --mmio-region 0x40000000 0x50000000 --arch ARMCortexM 
--entry-point 0x0 <PATH_TO_BLOB> --offset-ivt 0xa8
`

Notes: 
=====
AFAIK results are compatible with the one reported in the paper for the Nordic images.

WARNING: Base address detection for Texas Instrument firmware are trickier since the images are missing 
one (or multiple?) sections where sometimes function are jumping with absolute addresses. 

'''

import angr
import argparse
import logging
import os
import re 
import string
import shutil
import sys
sys.setrecursionlimit(10**9) 

from datetime import date, datetime
from cle.backends import NamedRegion

l = logging.getLogger("angr.firmxray")
l.setLevel(logging.DEBUG)

def auto_int(x):
    return int(x, 0)

def parse_opts():
    o = argparse.ArgumentParser()
    group_blob_type = o.add_mutually_exclusive_group()
    o.add_argument("--debug", action='store_true')
    o.add_argument('-Mr', '--mmio-region', action='append', nargs=2, type=auto_int, default=None)
    o.add_argument('-Rr', '--ram', nargs=2, type=auto_int, default=None)
    o.add_argument('-Sr', '--scb', nargs=2, type=auto_int, default=None)
    group_blob_type.add_argument("--cortexm", action='store_true')
    group_blob_type.add_argument("--generic", action='store_true')
    o.add_argument("--entry-point", type=auto_int, default=None)
    o.add_argument("--arch", default="ARMEL")
    o.add_argument("--offset-ivt", type=auto_int, default=None)
    o.add_argument("binary")
    opts = o.parse_args()
    return opts


def isascii(s):
    """Check if the characters in string s are in ASCII, U+0-U+7F."""
    return len(s) == len(s.encode())


def hunt_string(start_addr, blank_state):
    strings_collected = list()
    start_addr = start_addr
    curr_addr = start_addr
    maybe_string = []

    while True:
        try:
            char =  blank_state.solver.eval(blank_state.memory.load(curr_addr,1, endness="Iend_LE"))
        except Exception:
            break
        if char != 0:
            maybe_string.append(chr(char))
            curr_addr += 1
        else:
            break

    if len(maybe_string) != 0:
        maybe_string = ''.join(maybe_string)
        if isascii(maybe_string) and maybe_string.isprintable() and len(maybe_string) > 2:
            strings_collected.append((hex(start_addr), maybe_string))
    
    return strings_collected

def getStringReferences(project, cfg, load_immediate):
    
    l.info("getStringReferences from blob")
    all_strings_refs = []

    i = 0
    tot_func = len(list(project.kb.functions))

    blank_state = project.factory.blank_state()
    blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Load from previously collected loads 
    for a in set(load_immediate):
        all_strings_refs.extend(hunt_string(a, blank_state))

    now_len = len(all_strings_refs)

    # Load from function constants 
    for f in cfg.functions.values(): 
        #l.debug("[{}/{}] Analyzing function {}".format(i, tot_func, hex(f.addr)))
        i += 1 
        
        try:  
            absolute_addrs = set(f.code_constants)
        except Exception:
            continue

        for a in absolute_addrs:
            all_strings_refs.extend(hunt_string(a, blank_state))

    return all_strings_refs

def getImmediateLoad(project, cfg):
    l.info("GetImmediateLoad constants from blob")
    constants = set()
    i = 0
    tot_func = len(list(project.kb.functions))
    for func_addr, func in cfg.functions.items():
        i += 1
        
        #try:
        #    for x in func.code_constants:
        #        constants.add(x)
        #except Exception:
        #    continue

        #l.debug("[{}/{}] Analyzing function {}".format(i, tot_func, hex(func_addr)))
        for func_block in func.blocks:
            cb = func_block.capstone
            for instr in cb.insns:
                if "ldr" in instr.mnemonic or "ldmia" in instr.mnemonic:
                    for op in instr.insn.operands:
                        if op.type == 1:
                            reg_name = instr.insn.reg_name(op.reg)
                            call_state = project.factory.blank_state()
                            call_state.regs.pc = instr.insn.address
                            call_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                            call_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
                            simgr = project.factory.simgr(call_state)
                            simgr.step()
                            try:
                                new_state = simgr.active[0]
                                const = getattr(new_state.regs, reg_name)
                                constants.add(new_state.solver.eval(const))
                            except Exception:
                                pass
    return constants


'''
This is also not used in the implementation of FirmXRay (see source code).
'''
def getBxIns(project, cfg):
    """
    Not used as of now (as in the FirmXRay code)
    """
    l.info("getBxIns addr from blob")
    bxes = set()
    i = 0
    tot_func = len(list(project.kb.functions))
    for func_addr, func in cfg.functions.items():
        i += 1
        
        #try:
        #    for x in func.code_constants:
        #        constants.add(x)
        #except Exception:
        #    continue

        #l.debug("[{}/{}] Analyzing function {}".format(i, tot_func, hex(func_addr)))
        for func_block in func.blocks:
            cb = func_block.capstone
            for instr in cb.insns:
                if instr.mnemonic.startswith("bl") or instr.mnemonic.startswith("bx"):
                    assert(len(instr.insn.operands) == 1)
                    op = instr.insn.operands[0]
                    if op.type == 1:
                        reg_name = instr.insn.reg_name(op.reg)
                        if "lr" != reg_name:
                            bxes.add((hex(instr.insn.address), instr.insn))
    return bxes


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


# SOME HARDCODED CONSTANTS
MAX_BASE =  0x80000 #0x80000 #0x20000000
MIN_BASE = -1

# This is used in the searching algorithm 
# for candidate base addresses 
DELTA  = 0x100

if __name__ == "__main__":
    opts = parse_opts()
    blob_path = opts.binary

    if opts.cortexm:
        from .loaders.cortex_m import load_it, cfg_it
    else:
        from .loaders.generic import load_it, cfg_it

    p = load_it(opts.binary, 
                arch=opts.arch,
                mmio_regions=opts.mmio_region,
                base_addr=0x0,
                entry_point=opts.entry_point,
                offset_ivt=opts.offset_ivt,
                ram=opts.ram,
                scb=opts.scb
                )

    cfg = cfg_it(p)
    p.cfg = cfg
    p.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)
    p.cfg.do_full_xrefs()
    
    #bxes_instructions = getBxIns(p, p.cfg)

    load_immediate = getImmediateLoad(p, p.cfg)
    load_immediate = list(filter(lambda x: x < MAX_BASE, load_immediate))
    
    string_refs = set([x[0] for x in getStringReferences(p, p.cfg, load_immediate)])
    
    # Set of absolute strings addresses;
    absolute_string_refs = set()

    # We want ONLY absolute string addresses
    for st in string_refs:
        xrefs = p.kb.xrefs.get_xrefs_by_dst(int(st,16))
        if len(xrefs) != 0:
            for x in xrefs:
                ins_addr = x.ins_addr
                bbb = p.factory.block(ins_addr)

                if bbb.capstone.insns:
                    target_ins = bbb.capstone.insns[0]
                    # Filter relative loads (as FirmXRay does).
                    if target_ins.insn.mnemonic != "adr":
                        absolute_string_refs.add(int(st,16))

    absolute_string_refs = list(filter(lambda x: x < MAX_BASE, absolute_string_refs))
    l.debug("Number of absolute string pointers are {}".format(len(absolute_string_refs)))

    ivt_absolute_addresses = ExtractIVTAddresses(p, p.cfg, opts.offset_ivt)


    start_search = 0x0

    # Here FirmXRay says it uses min(), but `load_immediate` 
    # contains 0 and small values sometimes. I think it's
    # safer to use max. 
    # TODO We can be smarter in the search below (maybe implement bisection
    # or some smarter technique based on the progression of the score? ) 
    end_search = max(load_immediate)

    candidates = {}

    l.debug("Solving constraints...") 
    
    # Only search with even values
    for x in range(start_search, end_search, DELTA):
        # Set the score to 0 
        candidates[x] = 0
        
        # Checking if we have valid function entry. 
        for li in load_immediate:
            d = li - x
            if d % 2 == 0:
                d = d + 1 
            if d in list(p.kb.functions):
                candidates[x] += 1

        # Checking interrupt table (FIXME paper says e7?)
        for ivta in ivt_absolute_addresses:
            d = ivta - x
            if d % 2 == 0:
                d = d + 1 
            if d in list(p.kb.functions):
                candidates[x] += 1

        # Checking if we match string references.
        for str_addr in absolute_string_refs:
            d = str_addr - x 
            blank_state = p.factory.blank_state()
            blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            blank_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            if len(hunt_string(d, blank_state)) != 0:
                candidates[x] += 1

        if candidates[x] > 10:
            l.debug("Candidate {} score {}".format(hex(x), candidates[x]))
    
    if len(candidates) == 0:
        l.critical("No candidates for base address :-(")
        import ipdb; ipdb.set_trace()
        import sys 
        sys.exit(0)

    base_addr = max(candidates, key=candidates.get)
    l.info("BEST CANDIDATE BASE ADDRESS {}".format(hex(base_addr)))
    import ipdb; ipdb.set_trace()
