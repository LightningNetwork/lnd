#!/usr/bin/env python3
#
# To the extent possible under law, Yawning Angel has waived all copyright
# and related or neighboring rights to aez, using the Creative
# Commons "CC0" public domain dedication. See LICENSE or
# <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

#
# Dependencies: https://github.com/Maratyszcza/PeachPy
#
# python3 -m peachpy.x86_64 -mabi=goasm -S -o aez_amd64.s aez_amd64.py
#

from peachpy import *
from peachpy.x86_64 import *

cpuidParams = Argument(ptr(uint32_t))

with Function("cpuidAMD64", (cpuidParams,)):
    reg_params = registers.r15
    LOAD.ARGUMENT(reg_params, cpuidParams)

    MOV(registers.eax, [reg_params])
    MOV(registers.ecx, [reg_params+8])

    CPUID()

    MOV([reg_params], registers.eax)
    MOV([reg_params+4], registers.ebx)
    MOV([reg_params+8], registers.ecx)
    MOV([reg_params+12], registers.edx)

    RETURN()

with Function("resetAMD64SSE2", ()):
    PXOR(registers.xmm0, registers.xmm0)
    PXOR(registers.xmm1, registers.xmm1)
    PXOR(registers.xmm2, registers.xmm2)
    PXOR(registers.xmm3, registers.xmm3)
    PXOR(registers.xmm4, registers.xmm4)
    PXOR(registers.xmm5, registers.xmm5)
    PXOR(registers.xmm6, registers.xmm6)
    PXOR(registers.xmm7, registers.xmm7)
    PXOR(registers.xmm8, registers.xmm8)
    PXOR(registers.xmm9, registers.xmm9)
    PXOR(registers.xmm10, registers.xmm10)
    PXOR(registers.xmm11, registers.xmm10)
    PXOR(registers.xmm12, registers.xmm12)
    PXOR(registers.xmm13, registers.xmm13)
    PXOR(registers.xmm14, registers.xmm14)
    PXOR(registers.xmm15, registers.xmm15)
    RETURN()

a = Argument(ptr(const_uint8_t))
b = Argument(ptr(const_uint8_t))
c = Argument(ptr(const_uint8_t))
d = Argument(ptr(const_uint8_t))
dst = Argument(ptr(uint8_t))

with Function("xorBytes1x16AMD64SSE2", (a, b, dst)):
    reg_a = GeneralPurposeRegister64()
    reg_b = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_a, a)
    LOAD.ARGUMENT(reg_b, b)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_a = XMMRegister()
    xmm_b = XMMRegister()

    MOVDQU(xmm_a, [reg_a])
    MOVDQU(xmm_b, [reg_b])

    PXOR(xmm_a, xmm_b)

    MOVDQU([reg_dst], xmm_a)

    RETURN()

with Function("xorBytes4x16AMD64SSE2", (a, b, c, d, dst)):
    reg_a = GeneralPurposeRegister64()
    reg_b = GeneralPurposeRegister64()
    reg_c = GeneralPurposeRegister64()
    reg_d = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_a, a)
    LOAD.ARGUMENT(reg_b, b)
    LOAD.ARGUMENT(reg_c, c)
    LOAD.ARGUMENT(reg_d, d)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_a = XMMRegister()
    xmm_b = XMMRegister()
    xmm_c = XMMRegister()
    xmm_d = XMMRegister()

    MOVDQU(xmm_a, [reg_a])
    MOVDQU(xmm_b, [reg_b])
    MOVDQU(xmm_c, [reg_c])
    MOVDQU(xmm_d, [reg_d])

    PXOR(xmm_a, xmm_b)
    PXOR(xmm_c, xmm_d)
    PXOR(xmm_a, xmm_c)

    MOVDQU([reg_dst], xmm_a)

    RETURN()

#
#  AES-NI helper functions.
#
def aesenc4x1(o, j, i, l, z):
    AESENC(o, j)
    AESENC(o, i)
    AESENC(o, l)
    AESENC(o, z)

def aesenc4x2(o0, o1, j, i, l, z):
    AESENC(o0, j)
    AESENC(o1, j)
    AESENC(o0, i)
    AESENC(o1, i)
    AESENC(o0, l)
    AESENC(o1, l)
    AESENC(o0, z)
    AESENC(o1, z)

def aesenc4x4(o0, o1, o2, o3, j, i, l, z):
    AESENC(o0, j)
    AESENC(o1, j)
    AESENC(o2, j)
    AESENC(o3, j)
    AESENC(o0, i)
    AESENC(o1, i)
    AESENC(o2, i)
    AESENC(o3, i)
    AESENC(o0, l)
    AESENC(o1, l)
    AESENC(o2, l)
    AESENC(o3, l)
    AESENC(o0, z)
    AESENC(o1, z)
    AESENC(o2, z)
    AESENC(o3, z)

def aesenc4x8(o0, o1, o2, o3, o4, o5, o6, o7, j, i, l, z):
    AESENC(o0, j)
    AESENC(o1, j)
    AESENC(o2, j)
    AESENC(o3, j)
    AESENC(o4, j)
    AESENC(o5, j)
    AESENC(o6, j)
    AESENC(o7, j)
    AESENC(o0, i)
    AESENC(o1, i)
    AESENC(o2, i)
    AESENC(o3, i)
    AESENC(o4, i)
    AESENC(o5, i)
    AESENC(o6, i)
    AESENC(o7, i)
    AESENC(o0, l)
    AESENC(o1, l)
    AESENC(o2, l)
    AESENC(o3, l)
    AESENC(o4, l)
    AESENC(o5, l)
    AESENC(o6, l)
    AESENC(o7, l)
    AESENC(o0, z)
    AESENC(o1, z)
    AESENC(o2, z)
    AESENC(o3, z)
    AESENC(o4, z)
    AESENC(o5, z)
    AESENC(o6, z)
    AESENC(o7, z)

#
# Sigh.  PeachPy has "interesting" ideas of definitions for certain things,
# so just use the `zen` uarch, because it supports everything.
#

j = Argument(ptr(const_uint8_t))
i = Argument(ptr(const_uint8_t))
l = Argument(ptr(const_uint8_t))
k = Argument(ptr(const_uint8_t))
src = Argument(ptr(uint8_t))

with Function("aezAES4AMD64AESNI", (j, i, l, k, src, dst), target=uarch.zen):
    reg_j = GeneralPurposeRegister64()
    reg_i = GeneralPurposeRegister64()
    reg_l = GeneralPurposeRegister64()
    reg_k = GeneralPurposeRegister64()
    reg_src = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_j, j)
    LOAD.ARGUMENT(reg_i, i)
    LOAD.ARGUMENT(reg_l, l)
    LOAD.ARGUMENT(reg_k, k)
    LOAD.ARGUMENT(reg_src, src)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_state = XMMRegister()
    xmm_j = XMMRegister()
    xmm_i = XMMRegister()
    xmm_l = XMMRegister()
    xmm_zero = XMMRegister()

    MOVDQU(xmm_state, [reg_src])
    MOVDQA(xmm_j, [reg_j])
    MOVDQA(xmm_i, [reg_i])
    MOVDQA(xmm_l, [reg_l])

    PXOR(xmm_state, xmm_j)
    PXOR(xmm_i, xmm_l)
    PXOR(xmm_state, xmm_i)
    PXOR(xmm_zero, xmm_zero)

    MOVDQA(xmm_i, [reg_k])
    MOVDQA(xmm_j, [reg_k+16])
    MOVDQA(xmm_l, [reg_k+32])

    aesenc4x1(xmm_state, xmm_j, xmm_i, xmm_l, xmm_zero)

    MOVDQU([reg_dst], xmm_state)

    RETURN()

with Function("aezAES10AMD64AESNI", (l, k, src, dst), target=uarch.zen):
    reg_l = GeneralPurposeRegister64()
    reg_k = GeneralPurposeRegister64()
    reg_src = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_l, l)
    LOAD.ARGUMENT(reg_k, k)
    LOAD.ARGUMENT(reg_src, src)
    LOAD.ARGUMENT(reg_dst, dst)

    MOVDQU(xmm_state, [reg_src])
    MOVDQU(xmm_l, [reg_l])

    PXOR(xmm_state, xmm_l)

    MOVDQA(xmm_i, [reg_k])
    MOVDQA(xmm_j, [reg_k+16])
    MOVDQA(xmm_l, [reg_k+32])

    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)

    MOVDQU([reg_dst], xmm_state)

    RETURN()

def doubleBlock(blk, tmp0, tmp1, c):
    MOVDQA(tmp0, [c])
    PSHUFB(blk, tmp0)
    MOVDQA(tmp1, blk)
    PSRAD(tmp1, 31)
    PAND(tmp1, [c+16])
    PSHUFD(tmp1, tmp1, 0x93)
    PSLLD(blk, 1)
    PXOR(blk, tmp1)
    PSHUFB(blk, tmp0)

x = Argument(ptr(uint8_t))
consts = Argument(ptr(const_uint8_t))
sz = Argument(ptr(size_t))

with Function("aezCorePass1AMD64AESNI", (src, dst, x, i, l, k, consts, sz), target=uarch.zen):
    # This would be better as a port of the aesni pass_one() routine,
    # however that requires storing some intermediaries in reversed
    # form.

    reg_src = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()
    reg_x = GeneralPurposeRegister64()
    reg_tmp = GeneralPurposeRegister64()
    reg_l = GeneralPurposeRegister64()
    reg_bytes = GeneralPurposeRegister64()
    reg_idx = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_src, src)  # src pointer
    LOAD.ARGUMENT(reg_dst, dst)  # dst pointer
    LOAD.ARGUMENT(reg_x, x)
    LOAD.ARGUMENT(reg_l, l)      # e.L[]
    LOAD.ARGUMENT(reg_bytes, sz) # bytes remaining
    MOV(reg_idx, 1)              # Index into e.L[]

    xmm_j = XMMRegister()    # AESENC Round key J
    xmm_i = XMMRegister()    # AESENC Round key I
    xmm_l = XMMRegister()    # AESENC Round Key L
    xmm_x = XMMRegister()    # Checksum X
    xmm_iDbl = XMMRegister() # e.I[1]
    xmm_tmp0 = XMMRegister()
    xmm_tmp1 = XMMRegister()
    xmm_zero = XMMRegister() # [16]byte{0x00}

    xmm_o0 = XMMRegister()
    xmm_o1 = XMMRegister()
    xmm_o2 = XMMRegister()
    xmm_o3 = XMMRegister()
    xmm_o4 = XMMRegister()
    xmm_o5 = XMMRegister()
    xmm_o6 = XMMRegister()
    xmm_o7 = XMMRegister()

    MOVDQU(xmm_x, [reg_x])

    LOAD.ARGUMENT(reg_tmp, i)
    MOVDQU(xmm_iDbl, [reg_tmp])

    LOAD.ARGUMENT(reg_tmp, k)
    MOVDQU(xmm_i, [reg_tmp])
    MOVDQU(xmm_j, [reg_tmp+16])
    MOVDQU(xmm_l, [reg_tmp+32])

    LOAD.ARGUMENT(reg_tmp, consts) # doubleBlock constants

    PXOR(xmm_zero, xmm_zero)

    # Process 16 * 16 bytes at a time in a loop.
    vector_loop256 = Loop()
    SUB(reg_bytes, 256)
    JB(vector_loop256.end)
    with vector_loop256:
        # TODO: Make better use of registers, optimize scheduling.

        # o0 = aes4(o0 ^ J ^ I ^ L[1], keys) // E(1,1)
        # o1 = aes4(o1 ^ J ^ I ^ L[2], keys) // E(1,2)
        # o2 = aes4(o2 ^ J ^ I ^ L[3], keys) // E(1,3)
        # o3 = aes4(o3 ^ J ^ I ^ L[4], keys) // E(1,4)
        # o4 = aes4(o4 ^ J ^ I ^ L[5], keys) // E(1,5)
        # o5 = aes4(o5 ^ J ^ I ^ L[6], keys) // E(1,6)
        # o6 = aes4(o6 ^ J ^ I ^ L[7], keys) // E(1,7)
        # o7 = aes4(o7 ^ J ^ I ^ L[0], keys) // E(1,0)
        MOVDQU(xmm_o0, [reg_src+16])
        MOVDQU(xmm_o1, [reg_src+48])
        MOVDQU(xmm_o2, [reg_src+80])
        MOVDQU(xmm_o3, [reg_src+112])
        MOVDQU(xmm_o4, [reg_src+144])
        MOVDQU(xmm_o5, [reg_src+176])
        MOVDQU(xmm_o6, [reg_src+208])
        MOVDQU(xmm_o7, [reg_src+240])
        MOVDQA(xmm_tmp0, xmm_j) # tmp = j ^ iDbl
        PXOR(xmm_tmp0, xmm_iDbl)
        PXOR(xmm_o0, xmm_tmp0)
        PXOR(xmm_o1, xmm_tmp0)
        PXOR(xmm_o2, xmm_tmp0)
        PXOR(xmm_o3, xmm_tmp0)
        PXOR(xmm_o4, xmm_tmp0)
        PXOR(xmm_o5, xmm_tmp0)
        PXOR(xmm_o6, xmm_tmp0)
        PXOR(xmm_o7, xmm_tmp0)
        PXOR(xmm_o0, [reg_l+16])  # L[1]
        PXOR(xmm_o1, [reg_l+32])  # L[2]
        PXOR(xmm_o2, [reg_l+48])  # L[3]
        PXOR(xmm_o3, [reg_l+64])  # L[4]
        PXOR(xmm_o4, [reg_l+80])  # L[5]
        PXOR(xmm_o5, [reg_l+96])  # L[6]
        PXOR(xmm_o6, [reg_l+112]) # L[7]
        PXOR(xmm_o7, [reg_l])     # L[0]
        aesenc4x8(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_o4, xmm_o5, xmm_o6, xmm_o7, xmm_j, xmm_i, xmm_l, xmm_zero)

        # dst[  :] = in[  :] ^ o0
        # dst[32:] = in[32:] ^ o1
        # dst[64:] = in[64:] ^ o2
        # dst[96:] = in[96:] ^ o3
        # dst[128:] = in[128:] ^ o4
        # dst[160:] = in[160:] ^ o5
        # dst[192:] = in[192:] ^ o6
        # dst[224:] = in[224:] ^ o7
        MOVDQU(xmm_tmp0, [reg_src])
        MOVDQU(xmm_tmp1, [reg_src+32])
        PXOR(xmm_o0, xmm_tmp0)
        PXOR(xmm_o1, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+64])
        MOVDQU(xmm_tmp1, [reg_src+96])
        PXOR(xmm_o2, xmm_tmp0)
        PXOR(xmm_o3, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+128])
        MOVDQU(xmm_tmp1, [reg_src+160])
        PXOR(xmm_o4, xmm_tmp0)
        PXOR(xmm_o5, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+192])
        MOVDQU(xmm_tmp1, [reg_src+224])
        PXOR(xmm_o6, xmm_tmp0)
        PXOR(xmm_o7, xmm_tmp1)
        MOVDQU([reg_dst], xmm_o0)
        MOVDQU([reg_dst+32], xmm_o1)
        MOVDQU([reg_dst+64], xmm_o2)
        MOVDQU([reg_dst+96], xmm_o3)
        MOVDQU([reg_dst+128], xmm_o4)
        MOVDQU([reg_dst+160], xmm_o5)
        MOVDQU([reg_dst+192], xmm_o6)
        MOVDQU([reg_dst+224], xmm_o7)

        # o0 = aes4(o0 ^ I, keys) // E(0,0)
        # o1 = aes4(o1 ^ I, keys) // E(0,0)
        # o2 = aes4(o2 ^ I, keys) // E(0,0)
        # o3 = aes4(o3 ^ I, keys) // E(0,0)
        # o4 = aes4(o4 ^ I, keys) // E(0,0)
        # o5 = aes4(o5 ^ I, keys) // E(0,0)
        # o6 = aes4(o6 ^ I, keys) // E(0,0)
        # o7 = aes4(o7 ^ I, keys) // E(0,0)
        PXOR(xmm_o0, xmm_i)
        PXOR(xmm_o1, xmm_i)
        PXOR(xmm_o2, xmm_i)
        PXOR(xmm_o3, xmm_i)
        PXOR(xmm_o4, xmm_i)
        PXOR(xmm_o5, xmm_i)
        PXOR(xmm_o6, xmm_i)
        PXOR(xmm_o7, xmm_i)
        aesenc4x8(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_o4, xmm_o5, xmm_o6, xmm_o7, xmm_j, xmm_i, xmm_l, xmm_zero)

        # dst[ 16:] = o0 ^ in[ 16:]
        # dst[ 48:] = o1 ^ in[ 48:]
        # dst[ 80:] = o2 ^ in[ 80:]
        # dst[112:] = o3 ^ in[112:]
        # dst[144:] = o4 ^ in[144:]
        # dst[176:] = o5 ^ in[176:]
        # dst[208:] = o6 ^ in[208:]
        # dst[240:] = o7 ^ in[240:]
        MOVDQU(xmm_tmp0, [reg_src+16])
        MOVDQU(xmm_tmp1, [reg_src+48])
        PXOR(xmm_o0, xmm_tmp0)
        PXOR(xmm_o1, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+80])
        MOVDQU(xmm_tmp1, [reg_src+112])
        PXOR(xmm_o2, xmm_tmp0)
        PXOR(xmm_o3, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+144])
        MOVDQU(xmm_tmp1, [reg_src+176])
        PXOR(xmm_o4, xmm_tmp0)
        PXOR(xmm_o5, xmm_tmp1)
        MOVDQU(xmm_tmp0, [reg_src+208])
        MOVDQU(xmm_tmp1, [reg_src+240])
        PXOR(xmm_o6, xmm_tmp0)
        PXOR(xmm_o7, xmm_tmp1)
        MOVDQU([reg_dst+16], xmm_o0)
        MOVDQU([reg_dst+48], xmm_o1)
        MOVDQU([reg_dst+80], xmm_o2)
        MOVDQU([reg_dst+112], xmm_o3)
        MOVDQU([reg_dst+144], xmm_o4)
        MOVDQU([reg_dst+176], xmm_o5)
        MOVDQU([reg_dst+208], xmm_o6)
        MOVDQU([reg_dst+240], xmm_o7)

        # X ^= o0 ^ o1 ^ o2 ^ o3
        PXOR(xmm_x, xmm_o0)
        PXOR(xmm_x, xmm_o1)
        PXOR(xmm_x, xmm_o2)
        PXOR(xmm_x, xmm_o3)
        PXOR(xmm_x, xmm_o4)
        PXOR(xmm_x, xmm_o5)
        PXOR(xmm_x, xmm_o6)
        PXOR(xmm_x, xmm_o7)

        # doubleBlock(I)
        doubleBlock(xmm_iDbl, xmm_tmp0, xmm_tmp1, reg_tmp)

        # Update book keeping.
        ADD(reg_src, 256)
        ADD(reg_dst, 256)
        SUB(reg_bytes, 256)
        JAE(vector_loop256.begin)
    ADD(reg_bytes, 256)
    process_64bytes = Label()
    SUB(reg_bytes, 128)
    JB(process_64bytes)

    # Can I haz registers?
    xmm_src_l0 = xmm_tmp0
    xmm_src_l1 = xmm_tmp1
    xmm_src_r0 = xmm_o4 # Change these at your peril (tmp0 used in 8 * 16 path)
    xmm_src_r1 = xmm_o5
    xmm_src_r2 = xmm_o6
    xmm_src_r3 = xmm_o7

    #
    # Process 8 * 16 bytes.
    #

    # o0 = aes4(o0 ^ J ^ I ^ L[1], keys) // E(1,1)
    # o1 = aes4(o1 ^ J ^ I ^ L[2], keys) // E(1,2)
    # o2 = aes4(o2 ^ J ^ I ^ L[3], keys) // E(1,3)
    # o3 = aes4(o3 ^ J ^ I ^ L[4], keys) // E(1,4)
    MOVDQU(xmm_src_r0, [reg_src+16])
    MOVDQU(xmm_src_r1, [reg_src+48])
    MOVDQU(xmm_src_r2, [reg_src+80])
    MOVDQU(xmm_src_r3, [reg_src+112])
    MOVDQA(xmm_o0, xmm_src_r0)
    MOVDQA(xmm_o1, xmm_src_r1)
    MOVDQU(xmm_o2, xmm_src_r2)
    MOVDQU(xmm_o3, xmm_src_r3)
    MOVDQA(xmm_tmp0, xmm_j) # tmp0(src_l0) = j ^ iDbl)1
    PXOR(xmm_tmp0, xmm_iDbl)
    PXOR(xmm_o0, xmm_tmp0)
    PXOR(xmm_o1, xmm_tmp0)
    PXOR(xmm_o2, xmm_tmp0)
    PXOR(xmm_o3, xmm_tmp0)
    PXOR(xmm_o0, [reg_l+16]) # L[1]
    PXOR(xmm_o1, [reg_l+32]) # L[2]
    PXOR(xmm_o2, [reg_l+48]) # L[3]
    PXOR(xmm_o3, [reg_l+64]) # L[4]
    aesenc4x4(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[  :] = in[  :] ^ o0
    # dst[32:] = in[32:] ^ o1
    # dst[64:] = in[64:] ^ o2
    # dst[96:] = in[96:] ^ o3
    MOVDQU(xmm_src_l0, [reg_src])
    MOVDQU(xmm_src_l1, [reg_src+32])
    PXOR(xmm_o0, xmm_src_l0)
    PXOR(xmm_o1, xmm_src_l1)
    MOVDQU(xmm_src_l0, [reg_src+64])
    MOVDQU(xmm_src_l1, [reg_src+96])
    PXOR(xmm_o2, xmm_src_l0)
    PXOR(xmm_o3, xmm_src_l1)
    MOVDQU([reg_dst], xmm_o0)
    MOVDQU([reg_dst+32], xmm_o1)
    MOVDQU([reg_dst+64], xmm_o2)
    MOVDQU([reg_dst+96], xmm_o3)

    # o0 = aes4(o0 ^ I, keys) // E(0,0)
    # o1 = aes4(o1 ^ I, keys) // E(0,0)
    # o2 = aes4(o2 ^ I, keys) // E(0,0)
    # o3 = aes4(o3 ^ I, keys) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    PXOR(xmm_o1, xmm_i)
    PXOR(xmm_o2, xmm_i)
    PXOR(xmm_o3, xmm_i)
    aesenc4x4(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[ 16:] = o0 ^ in[ 16:]
    # dst[ 48:] = o1 ^ in[ 48:]
    # dst[ 80:] = o2 ^ in[ 80:]
    # dst[112:] = o3 ^ in[112:]
    PXOR(xmm_o0, xmm_src_r0)
    PXOR(xmm_o1, xmm_src_r1)
    PXOR(xmm_o2, xmm_src_r2)
    PXOR(xmm_o3, xmm_src_r3)
    MOVDQU([reg_dst+16], xmm_o0)
    MOVDQU([reg_dst+48], xmm_o1)
    MOVDQU([reg_dst+80], xmm_o2)
    MOVDQU([reg_dst+112], xmm_o3)

    # X ^= o0 ^ o1 ^ o2 ^ o3
    PXOR(xmm_x, xmm_o0)
    PXOR(xmm_x, xmm_o1)
    PXOR(xmm_x, xmm_o2)
    PXOR(xmm_x, xmm_o3)

    # Update book keeping.
    ADD(reg_src, 128)
    ADD(reg_dst, 128)
    ADD(reg_idx, 4)
    SUB(reg_bytes, 128)

    LABEL(process_64bytes)
    ADD(reg_bytes, 128)
    process_32bytes = Label()
    SUB(reg_bytes, 64)
    JB(process_32bytes)

    #
    # Process 4 * 16 bytes.
    #

    reg_l_offset = reg_tmp
    MOV(reg_l_offset, reg_idx)
    SHL(reg_l_offset, 4)
    ADD(reg_l_offset, reg_l) # reg_l_offset = reg_l + reg_idx*16 (L[i%8])

    # o0 = aes4(o0 ^ J ^ I ^ L[(i+0)%8], keys) // E(1,i)
    # o1 = aes4(o1 ^ J ^ I ^ L[(i+1)%8], keys) // E(1,i+1)
    MOVDQU(xmm_src_r0, [reg_src+16])
    MOVDQU(xmm_src_r1, [reg_src+48])
    MOVDQA(xmm_o0, xmm_src_r0)
    MOVDQA(xmm_o1, xmm_src_r1)
    PXOR(xmm_o0, xmm_j)
    PXOR(xmm_o1, xmm_j)
    PXOR(xmm_o0, xmm_iDbl)
    PXOR(xmm_o1, xmm_iDbl)
    PXOR(xmm_o0, [reg_l_offset])    # L[i]
    PXOR(xmm_o1, [reg_l_offset+16]) # L[i+1]
    aesenc4x2(xmm_o0, xmm_o1, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[:  ] = in[:  ] ^ o0
    # dst[32:] = in[32:] ^ o1
    MOVDQU(xmm_src_l0, [reg_src])
    MOVDQU(xmm_src_l1, [reg_src+32])
    PXOR(xmm_o0, xmm_src_l0)
    PXOR(xmm_o1, xmm_src_l1)
    MOVDQU([reg_dst], xmm_o0)
    MOVDQU([reg_dst+32], xmm_o1)

    # o0 = aes4(o0 ^ I, keys) // E(0,0)
    # o1 = aes4(o1 ^ I, keys) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    PXOR(xmm_o1, xmm_i)
    aesenc4x2(xmm_o0, xmm_o1, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[16:] = o0 ^ in[16:]
    # dst[48:] = o1 ^ in[48:]
    PXOR(xmm_o0, xmm_src_r0)
    PXOR(xmm_o1, xmm_src_r1)
    MOVDQU([reg_dst+16], xmm_o0)
    MOVDQU([reg_dst+48], xmm_o1)

    # X ^= o0 ^ o2
    PXOR(xmm_x, xmm_o0)
    PXOR(xmm_x, xmm_o1)

    # Update book keeping.
    ADD(reg_src, 64)
    ADD(reg_dst, 64)
    ADD(reg_idx, 2)
    SUB(reg_bytes, 64)

    LABEL(process_32bytes)
    ADD(reg_bytes, 64)
    out = Label()
    SUB(reg_bytes, 32)
    JB(out)

    #
    # Process 2 * 16 bytes
    #

    # Pick the final L from the table.  This is the only time
    # where wrapping needs to happen based on the index.
    AND(reg_idx, 7)
    SHL(reg_idx, 4)
    ADD(reg_l, reg_idx)       # reg_l += reg_idx (&L[i%8])

    # o0 = aes4(o0 ^ J ^ I ^ L[i%8], keys) // E(1,i)
    MOVDQU(xmm_src_r0, [reg_src+16])
    MOVDQA(xmm_o0, xmm_src_r0)
    PXOR(xmm_o0, xmm_j)
    PXOR(xmm_o0, xmm_iDbl)
    PXOR(xmm_o0, [reg_l])
    aesenc4x1(xmm_o0, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[:] = in[:] ^ o0
    MOVDQU(xmm_src_l0, [reg_src])
    PXOR(xmm_o0, xmm_src_l0)
    MOVDQU([reg_dst], xmm_o0)

    # o0 = aes4(o0 ^ I, keys) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    aesenc4x1(xmm_o0, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst[16:] = o0 ^ in[16:]
    PXOR(xmm_o0, xmm_src_r0)
    MOVDQU([reg_dst+16], xmm_o0)

    # X ^= o0
    PXOR(xmm_x, xmm_o0)

    LABEL(out)

    # Write back X.
    MOVDQU([reg_x], xmm_x)

    RETURN()

y = Argument(ptr(uint8_t))
s = Argument(ptr(const_uint8_t))

with Function("aezCorePass2AMD64AESNI", (dst, y, s, j, i, l, k, consts, sz), target=uarch.zen):
    reg_dst = GeneralPurposeRegister64()
    reg_y = GeneralPurposeRegister64()
    reg_s = GeneralPurposeRegister64()
    reg_j = GeneralPurposeRegister64()
    reg_l = GeneralPurposeRegister64()
    reg_tmp = GeneralPurposeRegister64()
    reg_bytes = GeneralPurposeRegister64()
    reg_idx = GeneralPurposeRegister64()
    reg_sp_save = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_dst, dst)  # dst pointer
    LOAD.ARGUMENT(reg_y, y)
    LOAD.ARGUMENT(reg_j, j)
    LOAD.ARGUMENT(reg_l, l)
    LOAD.ARGUMENT(reg_bytes, sz) # bytes remaining
    MOV(reg_idx, 1)              # Index into e.L[]

    xmm_j = XMMRegister()    # AESENC Round key J
    xmm_i = XMMRegister()    # AESENC Round key I
    xmm_l = XMMRegister()    # AESENC Round Key L
    xmm_s = XMMRegister()    # S
    xmm_y = XMMRegister()    # Checksum Y
    xmm_iDbl = XMMRegister() # e.I[1]
    xmm_zero = XMMRegister() # [16]byte{0x00}
    xmm_tmp0 = XMMRegister()

    o0 = XMMRegister()
    o1 = XMMRegister()
    o2 = XMMRegister()
    o3 = XMMRegister()
    o4 = XMMRegister()
    o5 = XMMRegister()
    o6 = XMMRegister()
    o7 = XMMRegister()

    LOAD.ARGUMENT(reg_tmp, k)
    MOVDQU(xmm_i, [reg_tmp])
    MOVDQU(xmm_j, [reg_tmp+16])
    MOVDQU(xmm_l, [reg_tmp+32])

    MOVDQU(xmm_y, [reg_y])

    LOAD.ARGUMENT(reg_tmp, i)
    MOVDQU(xmm_iDbl, [reg_tmp])

    LOAD.ARGUMENT(reg_tmp, consts)

    PXOR(xmm_zero, xmm_zero)

    LOAD.ARGUMENT(reg_s, s)
    MOVDQU(xmm_s, [reg_s])
    PXOR(xmm_s, [reg_j+16]) # S ^= J[1] (Once per call, in theory)

    # Save the stack pointer, align stack to 32 bytes, and allocate
    # 256 bytes of scratch space.
    MOV(reg_sp_save, registers.rsp)
    AND(registers.rsp, 0xffffffffffffffe0)
    SUB(registers.rsp, 256)

    # Name strategic offsets.
    mem_dst_l0 = [registers.rsp]
    mem_dst_r0 = [registers.rsp+16]
    mem_dst_l1 = [registers.rsp+32]
    mem_dst_r1 = [registers.rsp+48]
    mem_dst_l2 = [registers.rsp+64]
    mem_dst_r2 = [registers.rsp+80]
    mem_dst_l3 = [registers.rsp+96]
    mem_dst_r3 = [registers.rsp+112]
    mem_dst_l4 = [registers.rsp+128]
    mem_dst_r4 = [registers.rsp+144]
    mem_dst_l5 = [registers.rsp+160]
    mem_dst_r5 = [registers.rsp+176]
    mem_dst_l6 = [registers.rsp+192]
    mem_dst_r6 = [registers.rsp+208]
    mem_dst_l7 = [registers.rsp+224]
    mem_dst_r7 = [registers.rsp+240]

    #
    # Process 16 * 16 bytes at a time in a loop.
    #
    vector_loop256 = Loop()
    SUB(reg_bytes, 256)
    JB(vector_loop256.end)
    with vector_loop256:
        # o0 = aes4(J[1] ^ I ^ L[1] ^ S[:], keys) // E(1,1)
        # o1 = aes4(J[1] ^ I ^ L[2] ^ S[:], keys) // E(1,1)
        #  ...
        # o6 = aes4(J[1] ^ I ^ L[7] ^ S[:], keys) // E(1,1)
        # o7 = aes4(J[1] ^ I ^ L[0] ^ S[:], keys) // E(1,0)
        MOVDQA(xmm_o0, xmm_s)
        PXOR(xmm_o0, xmm_iDbl)    # o0 = s ^ I
        MOVDQA(xmm_o1, xmm_o0)    # o1 = o1
        MOVDQA(xmm_o2, xmm_o0)    # o2 = o1
        MOVDQA(xmm_o3, xmm_o0)    # o3 = o1
        MOVDQA(xmm_o4, xmm_o0)    # o1 = o1
        MOVDQA(xmm_o5, xmm_o0)    # o2 = o1
        MOVDQA(xmm_o6, xmm_o0)    # o3 = o1
        MOVDQA(xmm_o7, xmm_o0)    # o3 = o1
        PXOR(xmm_o0, [reg_l+16])  # o0 ^= L[1]
        PXOR(xmm_o1, [reg_l+32])  # o1 ^= L[2]
        PXOR(xmm_o2, [reg_l+48])  # o2 ^= L[3]
        PXOR(xmm_o3, [reg_l+64])  # o3 ^= L[4]
        PXOR(xmm_o4, [reg_l+80])  # o4 ^= L[5]
        PXOR(xmm_o5, [reg_l+96])  # o5 ^= L[6]
        PXOR(xmm_o6, [reg_l+112]) # o6 ^= L[7]
        PXOR(xmm_o7, [reg_l])     # o7 ^= L[0]
        aesenc4x8(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_o4, xmm_o5, xmm_o6, xmm_o7, xmm_j, xmm_i, xmm_l, xmm_zero)

        # TODO: Figure out how the fuck to remove some of these loads/stores.
        xmm_tmp1 = xmm_s # Use as scratch till the end of loop body.

        # dst_l0 ^= o0, ... dst_l7 ^= o7
        # Y ^= dst_l0 ^ ... ^ dst_l7
        MOVDQU(xmm_tmp0, [reg_dst])
        MOVDQU(xmm_tmp1, [reg_dst+32])
        PXOR(xmm_tmp0, xmm_o0)
        PXOR(xmm_tmp1, xmm_o1)
        PXOR(xmm_y, xmm_tmp0)
        PXOR(xmm_y, xmm_tmp1)
        MOVDQA(mem_dst_l0, xmm_tmp0)
        MOVDQA(mem_dst_l1, xmm_tmp1)

        MOVDQU(xmm_tmp0, [reg_dst+64])
        MOVDQU(xmm_tmp1, [reg_dst+96])
        PXOR(xmm_tmp0, xmm_o2)
        PXOR(xmm_tmp1, xmm_o3)
        PXOR(xmm_y, xmm_tmp0)
        PXOR(xmm_y, xmm_tmp1)
        MOVDQA(mem_dst_l2, xmm_tmp0)
        MOVDQA(mem_dst_l3, xmm_tmp1)

        MOVDQU(xmm_tmp0, [reg_dst+128])
        MOVDQU(xmm_tmp1, [reg_dst+160])
        PXOR(xmm_tmp0, xmm_o4)
        PXOR(xmm_tmp1, xmm_o5)
        PXOR(xmm_y, xmm_tmp0)
        PXOR(xmm_y, xmm_tmp1)
        MOVDQA(mem_dst_l4, xmm_tmp0)
        MOVDQA(mem_dst_l5, xmm_tmp1)

        MOVDQU(xmm_tmp0, [reg_dst+192])
        MOVDQU(xmm_tmp1, [reg_dst+224])
        PXOR(xmm_tmp0, xmm_o6)
        PXOR(xmm_tmp1, xmm_o7)
        PXOR(xmm_y, xmm_tmp0)
        PXOR(xmm_y, xmm_tmp1)
        MOVDQA(mem_dst_l6, xmm_tmp0)
        MOVDQA(mem_dst_l7, xmm_tmp1)

        # o0 ^= dst_r0, ... o7 ^= dst_r7
        # dst_r0 = o0, ... dst_r7 = o7
        MOVDQU(xmm_tmp0, [reg_dst+16])
        MOVDQU(xmm_tmp1, [reg_dst+48])
        PXOR(xmm_o0, xmm_tmp0)
        PXOR(xmm_o1, xmm_tmp1)
        MOVDQA(mem_dst_r0, xmm_o0)
        MOVDQA(mem_dst_r1, xmm_o1)

        MOVDQU(xmm_tmp0, [reg_dst+80])
        MOVDQU(xmm_tmp1, [reg_dst+112])
        PXOR(xmm_o2, xmm_tmp0)
        PXOR(xmm_o3, xmm_tmp1)
        MOVDQA(mem_dst_r2, xmm_o2)
        MOVDQA(mem_dst_r3, xmm_o3)

        MOVDQU(xmm_tmp0, [reg_dst+144])
        MOVDQU(xmm_tmp1, [reg_dst+176])
        PXOR(xmm_o4, xmm_tmp0)
        PXOR(xmm_o5, xmm_tmp1)
        MOVDQA(mem_dst_r4, xmm_o4)
        MOVDQA(mem_dst_r5, xmm_o5)

        MOVDQU(xmm_tmp0, [reg_dst+208])
        MOVDQU(xmm_tmp1, [reg_dst+240])
        PXOR(xmm_o6, xmm_tmp0)
        PXOR(xmm_o7, xmm_tmp1)
        MOVDQA(mem_dst_r6, xmm_o6)
        MOVDQA(mem_dst_r7, xmm_o7)

        # o0 = aes4(o0 ^ I[0]) // E(0,0)
        #  ...
        # o7 = aes4(o7 ^ I[0]) // E(0,0)
        PXOR(xmm_o0, xmm_i)
        PXOR(xmm_o1, xmm_i)
        PXOR(xmm_o2, xmm_i)
        PXOR(xmm_o3, xmm_i)
        PXOR(xmm_o4, xmm_i)
        PXOR(xmm_o5, xmm_i)
        PXOR(xmm_o6, xmm_i)
        PXOR(xmm_o7, xmm_i)
        aesenc4x8(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_o4, xmm_o5, xmm_o6, xmm_o7, xmm_j, xmm_i, xmm_l, xmm_zero)

        # o0 ^= dst_l0, ... o7 ^= dst_l7
        # dst_l0 = o0, ... dst_l7 = o7
        #
        # nb: Stored into the right hand blocks of dst[], because we are
        # done with the left hand side.
        PXOR(xmm_o0, mem_dst_l0)
        PXOR(xmm_o1, mem_dst_l1)
        PXOR(xmm_o2, mem_dst_l2)
        PXOR(xmm_o3, mem_dst_l3)
        PXOR(xmm_o4, mem_dst_l4)
        PXOR(xmm_o5, mem_dst_l5)
        PXOR(xmm_o6, mem_dst_l6)
        PXOR(xmm_o7, mem_dst_l7)
        MOVDQU([reg_dst+16], xmm_o0)
        MOVDQU([reg_dst+48], xmm_o1)
        MOVDQU([reg_dst+80], xmm_o2)
        MOVDQU([reg_dst+112], xmm_o3)
        MOVDQU([reg_dst+144], xmm_o4)
        MOVDQU([reg_dst+176], xmm_o5)
        MOVDQU([reg_dst+208], xmm_o6)
        MOVDQU([reg_dst+240], xmm_o7)

        # o0 = aes4(o0 ^ J[0] ^ I ^ L[1]) // E(1,1)
        # o1 = aes4(o0 ^ J[0] ^ I ^ L[2]) // E(1,2)
        #  ...
        # o6 = aes4(o0 ^ J[0] ^ I ^ L[7]) // E(1,7)
        # o7 = aes4(o0 ^ J[0] ^ I ^ L[0]) // E(1,0)
        MOVDQA(xmm_tmp0, [reg_j])
        PXOR(xmm_tmp0, xmm_iDbl)  # tmp = J[0] ^ I
        PXOR(xmm_o0, xmm_tmp0)    # o0 ^= tmp
        PXOR(xmm_o1, xmm_tmp0)    # o1 ^= tmp
        PXOR(xmm_o2, xmm_tmp0)    # o2 ^= tmp
        PXOR(xmm_o3, xmm_tmp0)    # o3 ^= tmp
        PXOR(xmm_o4, xmm_tmp0)    # o4 ^= tmp
        PXOR(xmm_o5, xmm_tmp0)    # o5 ^= tmp
        PXOR(xmm_o6, xmm_tmp0)    # o6 ^= tmp
        PXOR(xmm_o7, xmm_tmp0)    # o7 ^= tmp
        PXOR(xmm_o0, [reg_l+16])  # o0 ^= L[1]
        PXOR(xmm_o1, [reg_l+32])  # o1 ^= L[2]
        PXOR(xmm_o2, [reg_l+48])  # o2 ^= L[3]
        PXOR(xmm_o3, [reg_l+64])  # o3 ^= L[4]
        PXOR(xmm_o4, [reg_l+80])  # o4 ^= L[5]
        PXOR(xmm_o5, [reg_l+96])  # o5 ^= L[6]
        PXOR(xmm_o6, [reg_l+112]) # o6 ^= L[7]
        PXOR(xmm_o7, [reg_l])     # o7 ^= L[0]
        aesenc4x8(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_o4, xmm_o5, xmm_o6, xmm_o7, xmm_j, xmm_i, xmm_l, xmm_zero)

        # dst_r0 ^= o0, ... dst_r7 ^= o7
        # dst_l0, dst_r0 = dst_r0, dst_l0 ... dst_l7, dst_r7 = dst_r7, dst_l7
        #
        # nb: dst_l0 ... dst_l7 already written after the previous aesenc4x8
        # call.
        PXOR(xmm_o0, mem_dst_r0)
        PXOR(xmm_o1, mem_dst_r1)
        PXOR(xmm_o2, mem_dst_r2)
        PXOR(xmm_o3, mem_dst_r3)
        PXOR(xmm_o4, mem_dst_r4)
        PXOR(xmm_o5, mem_dst_r5)
        PXOR(xmm_o6, mem_dst_r6)
        PXOR(xmm_o7, mem_dst_r7)
        MOVDQU([reg_dst], xmm_o0)
        MOVDQU([reg_dst+32], xmm_o1)
        MOVDQU([reg_dst+64], xmm_o2)
        MOVDQU([reg_dst+96], xmm_o3)
        MOVDQU([reg_dst+128], xmm_o4)
        MOVDQU([reg_dst+160], xmm_o5)
        MOVDQU([reg_dst+192], xmm_o6)
        MOVDQU([reg_dst+224], xmm_o7)

        # doubleBlock(I)
        doubleBlock(xmm_iDbl, xmm_tmp0, xmm_tmp1, reg_tmp)

        MOVDQU(xmm_s, [reg_s])
        PXOR(xmm_s, [reg_j+16])  # Re-derive since it was used as scratch space.

        # Update book keeping.
        ADD(reg_dst, 256)
        SUB(reg_bytes, 256)
        JAE(vector_loop256.begin)

        # Purge the scratch space that we are done with.
        MOVDQA(mem_dst_r0, xmm_zero)
        MOVDQA(mem_dst_r1, xmm_zero)
        MOVDQA(mem_dst_r2, xmm_zero)
        MOVDQA(mem_dst_r3, xmm_zero)
        MOVDQA(mem_dst_l4, xmm_zero)
        MOVDQA(mem_dst_r4, xmm_zero)
        MOVDQA(mem_dst_l5, xmm_zero)
        MOVDQA(mem_dst_r5, xmm_zero)
        MOVDQA(mem_dst_l6, xmm_zero)
        MOVDQA(mem_dst_r6, xmm_zero)
        MOVDQA(mem_dst_l7, xmm_zero)
        MOVDQA(mem_dst_r7, xmm_zero)
    ADD(reg_bytes, 256)
    process_64bytes = Label()
    SUB(reg_bytes, 128)
    JB(process_64bytes)

    # Can I haz registers?
    xmm_dst_l0 = xmm_o4
    xmm_dst_r0 = xmm_o5
    xmm_dst_l1 = xmm_o6
    xmm_dst_r1 = xmm_o7

    #
    # Process 8 * 16 bytes.
    #

    # o0 = aes4(J[1] ^ I ^ L[1] ^ S[:], keys) // E(1,1)
    # o1 = aes4(J[1] ^ I ^ L[2] ^ S[:], keys) // E(1,2)
    # o2 = aes4(J[1] ^ I ^ L[3] ^ S[:], keys) // E(1,3)
    # o3 = aes4(J[1] ^ I ^ L[4] ^ S[:], keys) // E(1,4)
    MOVDQA(xmm_o0, xmm_s)
    PXOR(xmm_o0, xmm_iDbl)   # o0 = s ^ I
    MOVDQA(xmm_o1, xmm_o0)   # o1 = o0
    MOVDQA(xmm_o2, xmm_o0)   # o2 = o0
    MOVDQA(xmm_o3, xmm_o0)   # o3 = o0
    PXOR(xmm_o0, [reg_l+16]) # o0 ^= L[1]
    PXOR(xmm_o1, [reg_l+32]) # o1 ^= L[2]
    PXOR(xmm_o2, [reg_l+48]) # o2 ^= L[3]
    PXOR(xmm_o3, [reg_l+64]) # o3 ^= L[4]
    aesenc4x4(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_j, xmm_i, xmm_l, xmm_zero)

    # Load the left halfs of the dsts into registers.
    xmm_dst_l2 = xmm_dst_r0
    xmm_dst_l3 = xmm_dst_r1
    MOVDQU(xmm_dst_l0, [reg_dst])    # dst_l0 = dst[:]
    MOVDQU(xmm_dst_l1, [reg_dst+32]) # dst_l1 = dst[32:]
    MOVDQU(xmm_dst_l2, [reg_dst+64]) # dst_l2 = dst[64:]
    MOVDQU(xmm_dst_l3, [reg_dst+96]) # dst_l3 = dst[96:]

    # dst_l0 ^= o0, ... dst_l3 ^= o3
    PXOR(xmm_dst_l0, xmm_o0)
    PXOR(xmm_dst_l1, xmm_o1)
    PXOR(xmm_dst_l2, xmm_o2)
    PXOR(xmm_dst_l3, xmm_o3)

    # Y ^= dst_l0 ^ ... ^ dst_l3
    PXOR(xmm_y, xmm_dst_l0)
    PXOR(xmm_y, xmm_dst_l1)
    PXOR(xmm_y, xmm_dst_l2)
    PXOR(xmm_y, xmm_dst_l3)

    # Store the altered left halfs.
    MOVDQA(mem_dst_l0, xmm_dst_l0)
    MOVDQA(mem_dst_l1, xmm_dst_l1)
    MOVDQA(mem_dst_l2, xmm_dst_l2)
    MOVDQA(mem_dst_l3, xmm_dst_l3)

    # Load the right halfs of dst into registers.
    xmm_dst_r2 = xmm_dst_l0
    xmm_dst_r3 = xmm_dst_l1
    MOVDQU(xmm_dst_r0, [reg_dst+16])  # dst_r0 = dst[ 16:]
    MOVDQU(xmm_dst_r1, [reg_dst+48])  # dst_r1 = dst[ 48:]
    MOVDQU(xmm_dst_r2, [reg_dst+80])  # dst_r2 = dst[ 80:]
    MOVDQU(xmm_dst_r3, [reg_dst+112]) # dst_r3 = dst[112:]

    # o0 ^= dst_r0, ... o3 ^= dst_r3
    # dst_r0 = o0, ... dst_r3 = o3
    PXOR(xmm_o0, xmm_dst_r0)
    PXOR(xmm_o1, xmm_dst_r1)
    PXOR(xmm_o2, xmm_dst_r2)
    PXOR(xmm_o3, xmm_dst_r3)
    MOVDQU([reg_dst+16], xmm_o0)
    MOVDQU([reg_dst+48], xmm_o1)
    MOVDQU([reg_dst+80], xmm_o2)
    MOVDQU([reg_dst+112], xmm_o3)
    MOVDQA(xmm_dst_r0, xmm_o0)
    MOVDQA(xmm_dst_r1, xmm_o1)
    MOVDQA(xmm_dst_r2, xmm_o2)
    MOVDQA(xmm_dst_r3, xmm_o3)

    # o0 = aes4(o0 ^ I[0]) // E(0,0)
    #  ...
    # o3 = aes4(o3 ^ I[0]) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    PXOR(xmm_o1, xmm_i)
    PXOR(xmm_o2, xmm_i)
    PXOR(xmm_o3, xmm_i)
    aesenc4x4(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_j, xmm_i, xmm_l, xmm_zero)

    # o0 ^= dst_l0, ... o3 ^= dst_l3
    # dst_l0 = o0, ... dst_l3 = o3
    #
    # nb: Stored into the right hand blocks of dst[], because we are
    # done with the left hand side.
    PXOR(xmm_o0, mem_dst_l0)
    PXOR(xmm_o1, mem_dst_l1)
    PXOR(xmm_o2, mem_dst_l2)
    PXOR(xmm_o3, mem_dst_l3)
    MOVDQU([reg_dst+16], xmm_o0)
    MOVDQU([reg_dst+48], xmm_o1)
    MOVDQU([reg_dst+80], xmm_o2)
    MOVDQU([reg_dst+112], xmm_o3)

    # o0 = aes4(o0 ^ J[0] ^ I ^ L[1]) // E(1,1)
    # o1 = aes4(o1 ^ J[0] ^ I ^ L[2]) // E(1,2)
    # o2 = aes4(o2 ^ J[0] ^ I ^ L[3]) // E(1,3)
    # o3 = aes4(o3 ^ J[0] ^ I ^ L[4]) // E(1,4)
    PXOR(xmm_o0, [reg_j])
    PXOR(xmm_o1, [reg_j])
    PXOR(xmm_o2, [reg_j])
    PXOR(xmm_o3, [reg_j])
    PXOR(xmm_o0, xmm_iDbl)
    PXOR(xmm_o1, xmm_iDbl)
    PXOR(xmm_o2, xmm_iDbl)
    PXOR(xmm_o3, xmm_iDbl)
    PXOR(xmm_o0, [reg_l+16]) # o0 ^= L[1]
    PXOR(xmm_o1, [reg_l+32]) # o1 ^= L[2]
    PXOR(xmm_o2, [reg_l+48]) # o2 ^= L[3]
    PXOR(xmm_o3, [reg_l+64]) # o3 ^= L[4]
    aesenc4x4(xmm_o0, xmm_o1, xmm_o2, xmm_o3, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst_r0 ^= o0, ... dst_r3 ^= o3
    # dst_l0, dst_r0 = dst_r0, dst_l0 ... dst_l3, dst_r3 = dst_r, dst_l3
    #
    # nb: dst_l0 ... dst_l7 already written after the previous aesenc4x4
    # call.
    PXOR(xmm_o0, xmm_dst_r0)
    PXOR(xmm_o1, xmm_dst_r1)
    PXOR(xmm_o2, xmm_dst_r2)
    PXOR(xmm_o3, xmm_dst_r3)
    MOVDQU([reg_dst], xmm_o0)
    MOVDQU([reg_dst+32], xmm_o1)
    MOVDQU([reg_dst+64], xmm_o2)
    MOVDQU([reg_dst+96], xmm_o3)

    # Update book keeping.
    ADD(reg_dst, 128)
    ADD(reg_idx, 4)
    SUB(reg_bytes, 128)

    LABEL(process_64bytes)
    ADD(reg_bytes, 128)
    process_32bytes = Label()
    SUB(reg_bytes, 64)
    JB(process_32bytes)

    #
    # Process 4 * 16 bytes.
    #
    # (Scratch space unused past this point, working set fits into registers.)
    #

    reg_l_offset = reg_tmp
    MOV(reg_l_offset, reg_idx)
    SHL(reg_l_offset, 4)
    ADD(reg_l_offset, reg_l) # reg_l_offset = reg_l + reg_idx*16 (L[i%8])

    # o0 = aes4(J[1] ^ I ^ L[(i+0)%8] ^ S[:], keys) // E(1,i)
    # o1 = aes4(J[1] ^ I ^ L[(i+1)%8] ^ S[:], keys) // E(1,i+1)
    MOVDQA(xmm_o0, xmm_s)
    PXOR(xmm_o0, xmm_iDbl)          # o0 = s ^ I
    MOVDQA(xmm_o1, xmm_o0)          # o1 = o0
    PXOR(xmm_o0, [reg_l_offset])    # o0 ^= L[i]
    PXOR(xmm_o1, [reg_l_offset+16]) # o1 ^= L[i+1]
    aesenc4x2(xmm_o0, xmm_o1, xmm_j, xmm_i, xmm_l, xmm_zero)

    # Load dst into registers.
    MOVDQU(xmm_dst_l0, [reg_dst])    # dst_l0 = dst[:]
    MOVDQU(xmm_dst_r0, [reg_dst+16]) # dst_r0 = dst[16:]
    MOVDQU(xmm_dst_l1, [reg_dst+32]) # dst_l1 = dst[32:]
    MOVDQU(xmm_dst_r1, [reg_dst+48]) # dst_r1 = dst[48:]

    # dst_l0 ^= o0, dst_l1 ^= o1
    PXOR(xmm_dst_l0, xmm_o0)
    PXOR(xmm_dst_l1, xmm_o1)

    # Y ^= dst_l0 ^ dst_l1
    PXOR(xmm_y, xmm_dst_l0)
    PXOR(xmm_y, xmm_dst_l1)

    # o0 ^= dst_r0, o1 ^= dst_r1
    # dst_r0 = o0, dst_r1 = o1
    PXOR(xmm_o0, xmm_dst_r0)
    PXOR(xmm_o1, xmm_dst_r1)
    MOVDQA(xmm_dst_r0, xmm_o0)
    MOVDQA(xmm_dst_r1, xmm_o1)

    # o0 = aes4(o0 ^ I[0]) // E(0,0)
    # o1 = aes4(o1 ^ I[0]) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    PXOR(xmm_o1, xmm_i)
    aesenc4x2(xmm_o0, xmm_o1, xmm_j, xmm_i, xmm_l, xmm_zero)

    # o0 ^= dst_l0, o1 ^= dst_;1
    # dst_l0 = o0, dst_l1 = o1
    PXOR(xmm_o0, xmm_dst_l0)
    PXOR(xmm_o1, xmm_dst_l1)
    MOVDQA(xmm_dst_l0, xmm_o0)
    MOVDQA(xmm_dst_l1, xmm_o1)

    # o0 = aes4(o0 ^ J[0] ^ I ^ L[(i+0)%8]) // E(1,i)
    # o1 = aes4(o1 ^ J[0] ^ I ^ L[(i+1)%8]) // E(1,i+1)
    PXOR(xmm_o0, [reg_j])
    PXOR(xmm_o1, [reg_j])
    PXOR(xmm_o0, xmm_iDbl)
    PXOR(xmm_o1, xmm_iDbl)
    PXOR(xmm_o0, [reg_tmp])
    PXOR(xmm_o1, [reg_tmp+16])
    aesenc4x2(xmm_o0, xmm_o1, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst_r0 ^= o0
    # dst_r1 ^= o1
    PXOR(xmm_dst_r0, xmm_o0)
    PXOR(xmm_dst_r1, xmm_o1)

    # dst_l0, dst_r0 = dst_r0, dst_l0 .. dst_l1, dst_r1 = dst_r1, dst_l1
    MOVDQU([reg_dst], xmm_dst_r0)
    MOVDQU([reg_dst+16], xmm_dst_l0)
    MOVDQU([reg_dst+32], xmm_dst_r1)
    MOVDQU([reg_dst+48], xmm_dst_l1)

    # Update book keeping.
    ADD(reg_dst, 64)
    ADD(reg_idx, 2)
    SUB(reg_bytes, 64)

    LABEL(process_32bytes)
    ADD(reg_bytes, 64)
    out = Label()
    SUB(reg_bytes, 32)
    JB(out)

    #
    # Process 2 * 16 bytes
    #

    # Pick the final L from the table.  This is the only time
    # where wrapping needs to happen based on the index.
    AND(reg_idx, 7)
    SHL(reg_idx, 4)
    ADD(reg_l, reg_idx)       # reg_l += reg_idx (&L[i%8])

    # o0 = aes4(J[1] ^ I ^ L[i%8] ^ S[:], keys) // E(1,i)
    MOVDQA(xmm_o0, xmm_s)  # o0 = s
    PXOR(xmm_o0, xmm_iDbl) # o0 ^= I
    PXOR(xmm_o0, [reg_l])  # L[i%8]
    aesenc4x1(xmm_o0, xmm_j, xmm_i, xmm_l, xmm_zero)

    # Load dst into registers.
    MOVDQU(xmm_dst_l0, [reg_dst])    # dst_l = dst[:]
    MOVDQU(xmm_dst_r0, [reg_dst+16]) # dst_r = dst[16:]

    # dst_l ^= o0
    PXOR(xmm_dst_l0, xmm_o0)

    # Y ^= dst_l
    PXOR(xmm_y, xmm_dst_l0)

    # dst_r ^= o0
    PXOR(xmm_o0, xmm_dst_r0)
    MOVDQA(xmm_dst_r0, xmm_o0) # o0 = dst_r

    # o0 = aes4(o0 ^ I[0]) // E(0,0)
    PXOR(xmm_o0, xmm_i)
    aesenc4x1(xmm_o0, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst_l ^= o0
    PXOR(xmm_o0, xmm_dst_l0)
    MOVDQA(xmm_dst_l0, xmm_o0) # o0 = dst_l

    # o0 = aes4(o0 ^ J[0] ^ I ^ L[i%8]) // E(1,i)
    PXOR(xmm_o0, [reg_j])
    PXOR(xmm_o0, xmm_iDbl)
    PXOR(xmm_o0, [reg_l])
    aesenc4x1(xmm_o0, xmm_j, xmm_i, xmm_l, xmm_zero)

    # dst_r ^= o0
    PXOR(xmm_dst_r0, xmm_o0)

    # dst_l, dst_r = dst_r, dst_l
    MOVDQU([reg_dst], xmm_dst_r0)
    MOVDQU([reg_dst+16], xmm_dst_l0)

    LABEL(out)

    # Write back Y.
    MOVDQU([reg_y], xmm_y)

    # Paranoia, cleanse the scratch space.  Most of it is purged
    # at the end of the 16x16 loop, but the 8x16 case uses these 4.
    MOVDQA(mem_dst_l0, xmm_zero)
    MOVDQA(mem_dst_l1, xmm_zero)
    MOVDQA(mem_dst_l2, xmm_zero)
    MOVDQA(mem_dst_l3, xmm_zero)

    # Restore the stack pointer.
    MOV(registers.rsp, reg_sp_save)

    RETURN()
