import sys
from qiling import Qiling

TARGET_FUNC_ADDR    = 0x3322c   # Address of the function we are interested in
LIBC_START_ADDR     = 0x0c460   # Address where __libc_start_main is being called

def dumpContext(ql: Qiling):
    print("\nr0: 0x%x" % ql.reg.r0)
    print("\nr1: 0x%x" % ql.reg.r1)
    print("\nr2: 0x%x" % ql.reg.r2)
    print("\nr3: 0x%x" % ql.reg.r3)
    print("\npc: 0x%x" % ql.reg.pc)
    print("\nsp: 0x%x" % ql.reg.sp)
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.reg.write("r0", func_addr)
    
def indirect_write_reg_string(ql: Qiling, register_id, new_str):
    address = ql.mem.map_anywhere(len(new_str))
    ql.mem.string(address, new_str)
    ql.reg.write(register_id, address) # == (ql.reg.r0 = address) 
    
def target_hook(ql: Qiling):
    payload = "*#$^"
    
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.reg.arch_pc)
    indirect_write_reg_string(ql, "r0", payload)
    print("\n--------------\n")
    
def sandbox(path, rootfs, debug):    
    ql = Qiling(path, rootfs)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(target_hook, TARGET_FUNC_ADDR)     
    ql.debugger = debug
    ql.run(end=0x3330c)

if __name__ == "__main__":
    debug = False
    if len(sys.argv) > 1 and sys.argv[1] == "--gdb":
        debug = True
    
    path = ["/home/sgarcia/TFG/Fuzzing/Qiling/netgear/bin/upnpd"]
    rootfs = "/home/sgarcia/TFG/Firmware/netgear/R7000/squashfs-root"
    sandbox(path, rootfs, debug)
    