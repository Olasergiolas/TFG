import sys, argparse
from qiling import Qiling
from qiling.const import QL_ARCH

TARGET_FUNC_ADDR    = 0x3322c   # Address of the function we are interested in
TARGET_END_ADDR     = 0x3330c   # End fuzzing when reaching this address
LIBC_START_ADDR     = 0x0c460   # Address where __libc_start_main is being called
PAYLOAD             = b"*#$^"   # Default firmware header payload including the needed magic string

def dumpContext(ql: Qiling):
    print("\nr0: 0x%x" % ql.arch.regs.read("r0"))
    print("\nr1: 0x%x" % ql.arch.regs.read("r1"))
    print("\nr2: 0x%x" % ql.arch.regs.read("r2"))
    print("\nr3: 0x%x" % ql.arch.regs.read("r3"))
    print("\npc: 0x%x" % ql.arch.regs.read("pc"))
    print("\nsp: 0x%x" % ql.arch.regs.read("sp"))
    
def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.arch.regs.write("r0", func_addr)
    
def indirect_write_reg_bytes(ql: Qiling, register_id, bytes):
    address = ql.mem.map_anywhere(len(bytes))
    ql.mem.write(address, bytes)
    ql.arch.regs.write(register_id, address)
    
def readPayload(path):
    with open(path, 'rb') as f:
        return f.read()
    
def target_hook(ql: Qiling):
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.arch.regs.read("pc"))
    print("Using", PAYLOAD, "as payload\n")
    indirect_write_reg_bytes(ql, "r0", PAYLOAD)
    print("\n--------------\n")
    
def sandbox(path, rootfs, debug):    
    ql = Qiling(path, rootfs, archtype=QL_ARCH.ARM, ostype='linux')
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(target_hook, TARGET_FUNC_ADDR)     
    ql.debugger = debug
    ql.run(end=TARGET_END_ADDR)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emulate firmware header check function")
    parser.add_argument("-f", "--firmware", help="Firmware in .chk format", nargs=1)
    parser.add_argument("--gdb", help="Use gdb debugger", action="store_true")
    args = parser.parse_args()
    
    if args.firmware:
        PAYLOAD = readPayload(args.firmware[0])
    
    path = ["/home/sgarcia/TFG/Fuzzing/Qiling/netgear/bin/upnpd"]
    rootfs = "/home/sgarcia/TFG/Firmware/netgear/R7000/squashfs-root"
    sandbox(path, rootfs, args.gdb)
    