import string
import sys, argparse, subprocess, datetime
from gevent import sleep
from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE

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
    
def test_hook(ql: Qiling):
    dumpContext(ql)

def libc_start_main_redirect(ql: Qiling, func_addr = TARGET_FUNC_ADDR):
    ql.arch.regs.write("r0", func_addr)
    
def indirect_write_reg_bytes(ql: Qiling, register_id, bytes):
    address = ql.mem.map_anywhere(len(bytes))
    ql.mem.write(address, bytes)
    ql.arch.regs.write(register_id, address)
    
def target_hook(ql: Qiling):
    print("\n--------------\n")
    print("HOOK, PC: 0x%x" % ql.arch.regs.read("pc"))
    print("Using", PAYLOAD, "as payload\n")
    indirect_write_reg_bytes(ql, "r0", PAYLOAD)
    print("\n--------------\n")
    
def sandbox(path, rootfs, debug):    
    ql = Qiling(path, rootfs, archtype=QL_ARCH.ARM, ostype='linux')
    ql.verbose = QL_VERBOSE.DISABLED
    ql.hook_address(test_hook, 0x332d8)
    ql.hook_address(libc_start_main_redirect, LIBC_START_ADDR)
    ql.hook_address(target_hook, TARGET_FUNC_ADDR)     
    ql.debugger = debug
    ql.run(end=TARGET_END_ADDR)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz the upnpd daemon using Qiling to emulate the binary")
    parser.add_argument("-f", "--firmware", help="Firmware in .chk format", nargs=1, required=True)
    parser.add_argument("-s", "--seed", help="Initial seed for Radamsa", nargs=1, required=False, type=int)
    args = parser.parse_args()
    
    path = ["bin/upnpd"]
    rootfs = "/src/Firmware/netgear/R7000/squashfs-root"
    
    while True:
        command = 'radamsa '
        
        if args.seed:
            command += '--seed ' + "% s" % args.seed[0] + ' '
            args.seed[0] += 1
        
        PAYLOAD = subprocess.check_output(command + args.firmware[0], shell=True)
        try:
            sandbox(path, rootfs, debug=False)
        except:
            print("\nFOUND CRASH\n")
            ts = datetime.datetime.now().strftime("%m-%d-%Y_%H:%M:%S") + ".dmp"
            f = open(ts, "wb+")
            f.write(PAYLOAD)
            f.close()
            exit(1)
    