import sys, argparse
from qiling import Qiling

TARGET_FUNC_ADDR    = 0x105d8   # Address of the function we are interested in
LIBC_START_ADDR     = 0x10494   # Address where __libc_start_main is being called

INPUT_REPLACE       = "BBBBBBBBBBBBBBBBBBBBBBB"

def dumpContext(ql: Qiling):
    print("\nr0: 0x%x" % ql.arch.regs.read("r0"))
    print("\nr1: 0x%x" % ql.arch.regs.read("r1"))
    print("\nr2: 0x%x" % ql.arch.regs.read("r2"))
    print("\nr3: 0x%x" % ql.arch.regs.read("r3"))
    print("\npc: 0x%x" % ql.arch.regs.read("pc"))
    print("\nsp: 0x%x" % ql.arch.regs.read("sp"))
    
def replace_mem_address(ql: Qiling, target_str, new_str):
    mem=ql.mem.search(bytes(target_str))
    target_address = mem[0]
    print("\nTARGET LOCATED AT 0x%x\n" % target_address)
    ql.mem.write(target_address, bytes(new_str))
    
def write_mem_string(ql: Qiling, addr, new_str):
    ql.mem.string(addr, new_str)
    
def indirect_write_reg_string(ql: Qiling, register_id, new_str):
    address = ql.mem.map_anywhere(len(new_str))
    ql.mem.string(address, new_str)
    ql.arch.regs.write(register_id, address) # == (ql.reg.r0 = address) 
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.arch.regs.write("r0", func_addr)
    
def target_hook(ql: Qiling):
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.arch.regs.read("pc"))
    print("\nReplacing input param with %s...\n" % INPUT_REPLACE)
    indirect_write_reg_string(ql, "r0", INPUT_REPLACE)
    dumpContext(ql)
    print("\n--------------\n")
    
def sandbox(path, rootfs, debug):
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(target_hook, TARGET_FUNC_ADDR)     
    ql.debugger = debug
    ql.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emulate test cipher function")
    parser.add_argument("--gdb", help="Use gdb debugger", action="store_true")
    parser.add_argument("-r", "--replace", help='''Replace input with another string to
                        test Qiling hooking capabilities''', required=False)
    parser.add_argument("input", help="Input string", nargs=1)
    args = parser.parse_args()
    
    if args.replace:
        INPUT_REPLACE = INPUT_REPLACE = args.replace
    
    path = ["/src/Fuzzing/Qiling/PoC/bin/main_arm", args.input[0]]
    rootfs = "/usr/arm-linux-gnueabi"
    sandbox(path, rootfs, args.gdb)
    