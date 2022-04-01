import sys
sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.os.posix import syscall
from qiling.os.const import UINT, POINTER
import struct

def my_bind(ql: Qiling):
    params = ql.os.resolve_fcall_params({
        'fd': UINT,
        'addr': POINTER,
        'addrlen': UINT
    })

    bind_fd = params['fd']
    bind_addr = params['addr']
    bind_addrlen = params['addrlen']

    print(f'Hijack bind({bind_fd}, {bind_addr:#x}, {bind_addrlen})')
    # read from memory (start_address, len)
    data = ql.mem.read(bind_addr, bind_addrlen)
    # custom unpack (your own ql.unpack) of a C struct from memory
    # https://linux.die.net/man/7/ip -> struct
    sin_family = struct.unpack("<h", data[:2])[0] or ql.os.fd[bind_fd].family
    # little-endian short -> format_string -> https://docs.python.org/3/library/struct.html#format-strings
    port, host = struct.unpack(">HI", data[2:8])
    # big-endian unsigned short, unsigned int -> format_string
    print(f'[*] Socket Infos:')
    print(f'''
    Family: {sin_family}
    Port: {port} (no root: +8000)
    Host-interface?: {host}
    ''')
    return 0  # from syscall.ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen)


def my_syscall_write(ql: Qiling, write_fd, write_buf, write_count, *args, **kw):
    regreturn = 0

    try:
        buf = ql.mem.read(write_buf, write_count)
        ql.log.info("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        ql.os.fd[write_fd].write(buf)
        regreturn = write_count
    except:
        regreturn = -1
        ql.log.info("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))

    return regreturn

def my_sandbox(path, rootfs, ostype):
    ql = Qiling(path, rootfs, ostype = ostype, multithread = True)
    ql.os.root = True
    ql.os.set_syscall(0x04, my_syscall_write)
    ql.add_fs_mapper("/mnt/app/www","squashfs-root/mnt/app/www")
    #ql.os.set_api('bind', my_bind, QL_INTERCEPT.ENTER)  # intercepting the bind call on enter
    #ql.set_syscall("write", my_syscall_write, QL_INTERCEPT.ENTER)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["squashfs-root/usr/sbin/httpd",
                "-h", "/mnt/app/www", "-p", "8080"],
               "squashfs-root", "linux")
