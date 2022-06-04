import sys, os
from qiling import Qiling
from qiling.extensions.afl import ql_afl_fuzz

TARGET_FUNC_ADDR    = 0x3322c   # Address of the function we are interested in
TARGET_END_ADDR     = 0x3330c   # End fuzzing when reaching this address
LIBC_START_ADDR     = 0x0c460   # Address where __libc_start_main is being called

def testhook(ql: Qiling):
    print("\n\n TEST HOOK \n\n")
    #ql.reg.write("r2", 0x800)
    dumpContext(ql)

def dumpContext(ql: Qiling):
    print("\nr0: 0x%x" % ql.reg.r0)
    print("\nr1: 0x%x" % ql.reg.r1)
    print("\nr2: 0x%x" % ql.reg.r2)
    print("\nr3: 0x%x" % ql.reg.r3)
    print("\npc: 0x%x" % ql.reg.pc)
    print("\nsp: 0x%x" % ql.reg.sp)
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.reg.write("r0", func_addr)
    
def sandbox(path, rootfs, debug, param_file):    
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(testhook, 0x332d8)
    
    def place_input_callback(_ql: Qiling, input: bytes, _):
        address = _ql.mem.map_anywhere(len(input))
        
        print("\n\n FIRMWARE LENGTH (bytes): \n\n", len(input))
        
        #_ql.mem.write(address, input)
        #_ql.reg.write("r0", address)
        _ql.uc.mem_write(address, input)
        _ql.reg.write("r0", address)
        
        res = _ql.mem.read(address, len(input));
        print("\n\n FUNCTION INPUT BYTES: \n\n", input)
        print("\n\n BYTES STORED IN MEMORY: \n\n", res)
        
    def start_afl(_ql: Qiling):
        ql_afl_fuzz(_ql, param_file, place_input_callback, exits=[TARGET_END_ADDR])
    
    ql.hook_address(start_afl, TARGET_FUNC_ADDR)
    
    try:
        ql.run()
        os._exit(0)
    except:
        os._exit(1)

if __name__ == "__main__":
    debug = False
    
    if len(sys.argv) == 1:
        raise ValueError("No input file")
    
    path = ["bin/upnpd"]
    rootfs = "/src/Firmware/netgear/R7000/squashfs-root"
    sandbox(path, rootfs, debug, sys.argv[1])
    