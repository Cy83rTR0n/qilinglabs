from qiling import Qiling
from qiling.const import *
from qiling.os.const import *
import struct


ql = Qiling([r'qilinglab-aarch64'],r'/home/firmware/qiling/examples/rootfs/arm64_linux',verbose=QL_VERBOSE.OFF)
base_addr = ql.mem.get_lib_base(ql.path)

#this challenge teaches us how to write to a specific address using qiling framework

def challenge1(ql):
    ql.mem.map(0x1000,0x1000)
    ql.mem.write(0x1337,ql.pack16s(1337))
    # print(f"value @0x1337 : {ql.unpack16s(ql.mem.read(0x1337,2))}")

#this challenge teaches us to hook a syscall and then modify the values for its arguments

def challenge2_callback(ql, *args):
    params = ql.os.resolve_fcall_params({'buf':POINTER})
    # print(f"{params}")
    struct_addr = params['buf']
    sysname = ql.mem.read(struct_addr,65)
    version = ql.mem.read(struct_addr+65*3,65)
    # print(f"sysname : {sysname}")
    # print(f"version : {version}")
    # print(f"{ql.mem.read(ql.arch.regs.sp+0xed,65)}")
    ql.mem.write(struct_addr+65*3,b"ChallengeStart\x00")
    version = ql.mem.read(struct_addr+65*3,65)
    # print(f"version : {version}")

def challenge2(ql):
    ql.os.set_syscall('uname',challenge2_callback,QL_INTERCEPT.EXIT)

#this challenge teaches us to hook syscalls and then modify them accordingly

def challenge3_read_callback(ql,*args):
    params = ql.os.resolve_fcall_params({'fd':INT,'buf':POINTER,'size':INT})
    if params['size'] == 32:
        bytes_20 = params['buf']
        # print(f"Before Moifying bytes_20 : {ql.mem.read(bytes_20,20)}")
        ql.mem.write(bytes_20,b"\xff"*32)
        # print(f"After Moifying bytes_20 : {ql.mem.read(bytes_20,20)}")
    if params['size'] == 1:
        bytes_1 = params['buf']
        # print(f"Before Modifying bytes_1 : {ql.mem.read(bytes_1,1)}")
        ql.mem.write(bytes_1,b"\xfe")
        # print(f"After Moifying bytes_20 : {ql.mem.read(bytes_1,1)}")

def challenge3_getrandom_callback(ql,*args):
    params = ql.os.resolve_fcall_params({'buf':POINTER,'size':INT})
    bytes_20 = params['buf']
    # print(f"Before Modifying bytes_20 : {ql.mem.read(bytes_20,20)}")
    ql.mem.write(bytes_20,b"\xff"*32)
    # print(f"After Moifying bytes_20 : {ql.mem.read(bytes_20,20)}")

def challenge3(ql):
    ql.os.set_syscall('read',challenge3_read_callback,QL_INTERCEPT.EXIT)
    ql.os.set_syscall('getrandom',challenge3_getrandom_callback,QL_INTERCEPT.EXIT)


def challenge4_callback(ql,*args):
    # print(f"{ql.arch.regs.x0}:{ql.arch.regs.x1}")
    ql.arch.regs.x0 = 1

def challenge4(ql):
    hook_addr = base_addr + 0xfe0
    ql.hook_address(challenge4_callback,hook_addr)

def challenge5_callback(ql):
    # print(f"BEFORE : {ql.arch.regs.x0}")
    ql.arch.regs.x0 = 0
    # print(f"AFTER : {ql.arch.regs.x0}")

def challenge5(ql):
    ql.os.set_api('rand',challenge5_callback,QL_INTERCEPT.CALL)

def challenge6_callback(ql,*args):
    ql.arch.regs.x0 = 0

def challenge6(ql):
    hook_addr = base_addr + 0x1118
    ql.hook_address(challenge6_callback,hook_addr)


def challenge7_callback(ql,*args):
    params = ql.os.resolve_fcall_params({'s':INT})
    params['s'] = 0

def challenge7(ql):
    ql.os.set_api('sleep',challenge7_callback,QL_INTERCEPT.CALL)

def challenge8_callback(ql):
    struct_addr = ql.unpack64(ql.mem.read(ql.arch.regs.sp+0x28,8))
    # print(f"{struct_addr}")
    actual_struct = ql.mem.read(struct_addr,24)
    field_1,field_2,field_3 = struct.unpack('QQQ',actual_struct)
    # print(f"f1:{field_1}")
    # print(f"f2:{field_2}")
    # print(f"f3:{field_3}")
    ql.mem.write(field_3,b"\x01")

def challenge8(ql):
    hook_addr = base_addr+0x11dc
    ql.hook_address(challenge8_callback,hook_addr)         


def challenge9_callback(ql):
    ql.arch.regs.x0 = 0

def challenge9(ql):
    hook_addr = base_addr + 0x1284
    ql.hook_address(challenge9_callback,hook_addr)

def challenge10_callback(ql):
    ql.arch.regs.x0 = 0
    # params = ql.os.resolve_fcall_params({'s1':POINTER,'s2':POINTER})
    # print(f"string1 : {ql.unpack64(ql.mem.read(params['s1'],8))}")
    # print(f"string2 : {ql.unpack64(ql.mem.read(params['s2'],8))}")
def challenge10(ql):
    hook_addr = base_addr + 0x1398
    ql.hook_address(challenge10_callback,hook_addr)
    # ql.os.set_api('strcmp',challenge10_callback,QL_INTERCEPT.CALL)

def challenge11_callback(ql):
    ql.arch.regs.x0 = ql.arch.regs.x1

def challenge11(ql):
    hook_addr = base_addr + 0x1400
    ql.hook_address(challenge11_callback,hook_addr)


challenge1(ql)
challenge2(ql)
challenge3(ql)
challenge4(ql)
challenge5(ql)
challenge6(ql)
challenge7(ql)
challenge8(ql)
challenge9(ql)
challenge10(ql)
challenge11(ql)
ql.run()
