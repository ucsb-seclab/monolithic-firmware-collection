import angr
import archinfo
import logging
import claripy
import struct

from cle.backends import NamedRegion
from angr.analyses.cfg import CFGUtils

l = logging.getLogger("loaders.CortexM")
l.setLevel("DEBUG")

def parse_cortexm_ivt(stream, offset_ivt=0, arch=None, my_base_addr=None, my_entry_point=None, my_stack_pointer=None):
    """
    :param stream:
    :type stream: file
    :return:
    """
    min_arm_sp = 0x1FFF0000
    max_arm_sp = 0x20100000

    stream.seek(offset_ivt)

    try:
        maybe_sp = stream.read(4)
        if my_stack_pointer:
            maybe_sp = my_stack_pointer
        maybe_le_sp = struct.unpack('<I', maybe_sp)[0]
        return maybe_le_sp
    except Exception:
        pass
    return None 
        


def load_it(fname, arch="ARMCortexM", base_addr=None, entry_point=None, offset_ivt=0, stack_pointer=None, ram=None, scb=None, mmio_regions=[]):
    
    maybe_arch = arch
    maybe_base = base_addr
    maybe_entry = entry_point
    maybe_sp = stack_pointer

    blob_stream = open(fname, "rb")

    maybe_sp = parse_cortexm_ivt(blob_stream,
                                offset_ivt=offset_ivt, 
                                arch=arch, 
                                my_base_addr=base_addr, 
                                my_entry_point=entry_point, 
                                my_stack_pointer=stack_pointer)

    assert(maybe_arch)
    assert(maybe_base != None)
    assert(maybe_entry != None)
    assert(maybe_sp != None)

    # Create project with information retrieved before.
    p = angr.Project(fname, main_opts={'base_addr': 0x0, 
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
        p.arch.initial_sp = maybe_sp
    return p


def cfg_it(p):
    cfg = p.analyses.CFG(resolve_indirect_jumps=True, 
                         cross_references=True, 
                         function_prologues=True, # force detection using ARM's function prologues.
                         show_progressbar=False,
                         normalize=True, symbols=True, start_at_entry=True)
    _ = p.analyses.CompleteCallingConventions(recover_variables=True, force=True)
    return cfg

