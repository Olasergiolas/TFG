import sys, os
from qiling import Qiling
from qiling.extensions.afl import ql_afl_fuzz

TARGET_FUNC_ADDR    = 0x3322c   # Address of the function we are interested in
TARGET_END_ADDR     = 0x3330c   # End fuzzing when reaching this address
LIBC_START_ADDR     = 0x0c460   # Address where __libc_start_main is being called
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.arch.regs.write("r0", func_addr)
    
def sandbox(path, rootfs, debug, param_file):
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    
    def place_input_callback(_ql: Qiling, input: bytes, _):
        address = _ql.mem.map_anywhere(len(input))
        
        print("\n FILE CONTENT: ", readPayload(sys.argv[1]))
        print("\n\n FILE LENGTH (bytes): ", len(input))
        
        _ql.mem.write(address, input)
        _ql.arch.regs.write("r0", address)
        
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
        
def readPayload(path):
    with open(path, 'rb') as f:
        return f.read()

if __name__ == "__main__":
    debug = False
    
    if len(sys.argv) == 1:
        raise ValueError("No input file")
    
    path = ["/home/sgarcia/TFG/Fuzzing/Qiling/netgear/bin/upnpd"]
    rootfs = "/home/sgarcia/TFG/Firmware/netgear/R7000/squashfs-root"
    sandbox(path, rootfs, debug, sys.argv[1])
    