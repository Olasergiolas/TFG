import sys
from qiling import Qiling

TARGET_FUNC_ADDR    = 0x10500   # Address of the function we are interested in
LIBC_START_ADDR     = 0x103cc   # Address where __libc_start_main is being called

def dumpContext(ql: Qiling):
    print("\nr0: 0x%x" % ql.reg.r0)
    print("\nr1: 0x%x" % ql.reg.r1)
    print("\nr2: 0x%x" % ql.reg.r2)
    print("\nr3: 0x%x" % ql.reg.r3)
    print("\npc: 0x%x" % ql.reg.pc)
    print("\nsp: 0x%x" % ql.reg.sp)
    
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
    ql.reg.write(register_id, address) # == (ql.reg.r0 = address) 
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.reg.write("r0", func_addr)
    
def target_hook(ql: Qiling):
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.reg.arch_pc)
    print("\nReplacing param...\n")
    indirect_write_reg_string(ql, "r0", "BBBBBBBBBBBBBBBBBBBBBBB")
    dumpContext(ql)
    print("\n--------------\n")
    
def sandbox(path, rootfs, debug):
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(target_hook, TARGET_FUNC_ADDR)     
    ql.debugger = debug
    ql.run()

if __name__ == "__main__":
    debug = False
    if len(sys.argv) > 1 and sys.argv[1] == "--gdb":
        debug = True
    
    print(sys.argv)
    path = ["/home/sgarcia/TFG/Fuzzing/Qiling/PoC/bin/main_arm", "ABC"]
    rootfs = "/usr/arm-linux-gnueabi"
    sandbox(path, rootfs, debug)
    