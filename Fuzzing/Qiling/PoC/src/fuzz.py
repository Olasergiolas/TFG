import sys, os
from qiling import Qiling
from qiling.extensions.afl import ql_afl_fuzz
from qiling.const import QL_VERBOSE

TARGET_FUNC_ADDR    = 0x105d8   # Address of the function we are interested in
TARGET_END_ADDR     = 0x1064c   # End fuzzing when reaching this address
LIBC_START_ADDR     = 0x10494   # Address where __libc_start_main is being called

def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.arch.regs.write("r0", func_addr)
    
def sandbox(path, rootfs, debug, param_file):    
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    
    def place_input_callback(_ql: Qiling, input: bytes, _):
        address = _ql.mem.map_anywhere(len(input))
        _ql.mem.write(address, input)
        _ql.arch.regs.write("r0", address)
    
    def start_afl(_ql: Qiling):
        ql_afl_fuzz(_ql, param_file, place_input_callback, exits=[ql.os.exit_point])
    
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
    
    path = ["bin/main_arm", "ABC"]
    rootfs = "/usr/arm-linux-gnueabi"
    sandbox(path, rootfs, debug, sys.argv[1])
    