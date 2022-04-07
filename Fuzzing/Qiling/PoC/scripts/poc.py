from audioop import add
import sys

sys.path.append("..")

from qiling import Qiling

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
    
def indirect_mem_map_and_replace(ql: Qiling, register_id, new_str):
    address = ql.mem.map_anywhere(len(new_str))
    ql.mem.string(address, new_str)
    ql.reg.write("r0", address) # == (ql.reg.r0 = address) 
    
def sandbox(path, rootfs, debug):
    ql = Qiling(path, rootfs)
    ql.hook_address(dump_hook, 0x10500)     # Address of the function we are interested in
    ql.debugger = debug
    ql.run()
    
def dump_hook(ql: Qiling):
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.reg.arch_pc)
    print("\nReplacing param...\n")
    indirect_mem_map_and_replace(ql, "r0", "BBBBBBBBBBBBBBBBBBBBBBB")
    dumpContext(ql)
    print("\n--------------\n")

if __name__ == "__main__":
    debug = False
    if len(sys.argv) > 1 and sys.argv[1] == "--gdb":
        debug = True
    
    print(sys.argv)
    path = ["/home/sgarcia/TFG/Fuzzing/Qiling/PoC/bin/main_arm", "ABC"]
    rootfs = "/usr/arm-linux-gnueabi"
    sandbox(path, rootfs, debug)
    