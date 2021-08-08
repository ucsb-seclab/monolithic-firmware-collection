import angr
import archinfo
import logging
import claripy
import struct

from cle.backends import NamedRegion
from angr.analyses.cfg import CFGUtils

l = logging.getLogger("loaders.GenericBlob")

def parse_blob():
    pass


def load_it(fname, arch=None, base_addr=None, entry_point=None, stack_pointer=None, ram=None, scb=None, mmio_regions=[]):
    
    maybe_arch = arch
    maybe_base = base_addr
    maybe_entry = entry_point
    maybe_sp = stack_pointer

    blob_stream = open(fname, "rb")
    # Parse it? 
    
    assert(maybe_arch)
    assert(maybe_base != None)
    assert(maybe_entry != None)
    assert(maybe_sp != None)

    # Create project with information retrieved before.
    p = angr.Project(fname, main_opts={'base_addr': maybe_base, 
                                       'arch': maybe_arch, 
                                       'entry_point': maybe_entry, 
                                       'backend': 'blob'})
    
    region_count = 0
    if ram:
        assert(ram[1] > ram[0])
        region = NamedRegion("ram", ram[0], ram[1])
        p.loader.dynamic_load(region)
    if scb:
        assert(scb[1] > scb[0])
        region = NamedRegion("scb", scb[0], scb[1])
        p.loader.dynamic_load(region)
    for start, end in mmio_regions:
        assert(end > start)
        region = NamedRegion("mmio%d" % region_count, start, end)
        p.loader.dynamic_load(region)
    
    # In Cortex-M the sp is the first DWORD according to the specification
    # of the memory layout.
    if stack_pointer:
        p.arch.initial_sp = stack_pointer
    else:
        blank_state = p.factory.blank_state()
        blob_stack_ptr = blank_state.mem_concrete(p.loader.main_object.min_addr,
                                                p.arch.bits//8, 
                                                endness=p.arch.memory_endness)

        # If odd addresses let's round to the lower even dword
        if blob_stack_ptr % 2 == 1:
            blob_stack_ptr = blob_stack_ptr & 0xfffffff8
        
        p.arch.initial_sp = blob_stack_ptr
    return p


def cfg_it(p):
    cfg = p.analyses.CFG(resolve_indirect_jumps=True, 
                         cross_references=True, 
                         force_complete_scan=False, 
                         show_progressbar=True,
                         normalize=True, symbols=True, start_at_entry=True)
    _ = p.analyses.CompleteCallingConventions(recover_variables=True, force=True)
    return cfg

