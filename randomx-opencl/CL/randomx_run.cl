/*
Copyright (c) 2019 SChernykh
Portions Copyright (c) 2018-2019 tevador

This file is part of RandomX OpenCL.

RandomX OpenCL is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

RandomX OpenCL is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with RandomX OpenCL. If not, see <http://www.gnu.org/licenses/>.
*/

#include "randomx_constants.h"
#include "randomx_constants_jit.h"

#define REGISTERS_COUNT (REGISTERS_SIZE / 8)

#define CacheLineSize 64U
#define CacheLineAlignMask ((1U << 31) - 1) & ~(CacheLineSize - 1)

#define mantissaSize 52
#define dynamicExponentBits 4
#define dynamicMantissaMask ((1UL << (mantissaSize + dynamicExponentBits)) - 1)

double load_F_E_groups(int value, ulong andMask, ulong orMask)
{
	ulong x = as_ulong(convert_double_rte(value));
	x &= andMask;
	x |= orMask;
	return as_double(x);
}

// This kernel is only used to dump binary and disassemble it into randomx_run.asm
__attribute__((reqd_work_group_size(32, 1, 1)))
__kernel void randomx_run(__global const uchar* dataset, __global uchar* scratchpad, __global ulong* registers, __global uint* rounding_modes, __global uint* programs, uint batch_size, uint rx_parameters)
{
	__local ulong2 R_buf[REGISTERS_COUNT / 2];

	const uint idx = get_group_id(0);
	const uint sub = get_local_id(0);

	const uint program_iterations = 1U << (rx_parameters >> 15);
	const uint ScratchpadL3Size = 1U << ((rx_parameters >> 10) & 31);
	const uint ScratchpadL3Mask64 = ScratchpadL3Size - 64;

	__local ulong* R = (__local ulong*)(R_buf);

	__local double* F = (__local double*)(R + 8);
	__local double* E = (__local double*)(R + 16);

	registers += idx * REGISTERS_COUNT;
	scratchpad += idx * (ulong)(ScratchpadL3Size + 64);
	rounding_modes += idx;
	programs += get_group_id(0) * (COMPILED_PROGRAM_SIZE / sizeof(uint));

	// Copy registers (256 bytes) into shared memory: 32 workers, 8 bytes for each worker
	((__local ulong*) R)[sub] = ((__global ulong*) registers)[sub];
	barrier(CLK_LOCAL_MEM_FENCE);

	if (sub >= 8)
		return;

	uint mx = ((__local uint*)(R + 16))[1];
	uint ma = ((__local uint*)(R + 16))[0];

	const uint readReg0 = ((__local uint*)(R + 17))[0];
	const uint readReg1 = ((__local uint*)(R + 17))[1];
	const uint readReg2 = ((__local uint*)(R + 17))[2];
	const uint readReg3 = ((__local uint*)(R + 17))[3];

	const uint datasetOffset = ((__local uint*)(R + 19))[0];
	dataset += datasetOffset;

	uint spAddr0 = mx;
	uint spAddr1 = ma;

	const bool f_group = (sub < 4);
	__local double* fe = f_group ? (F + sub * 2) : (E + (sub - 4) * 2);

	const ulong andMask = f_group ? (ulong)(-1) : dynamicMantissaMask;
	const ulong orMask1 = f_group ? 0 : R[20];
	const ulong orMask2 = f_group ? 0 : R[21];

	#pragma unroll(1)
	for (uint ic = 0; ic < program_iterations; ++ic)
	{
		const uint2 spMix = as_uint2(R[readReg0] ^ R[readReg1]);
		spAddr0 ^= spMix.x;
		spAddr0 &= ScratchpadL3Mask64;
		spAddr1 ^= spMix.y;
		spAddr1 &= ScratchpadL3Mask64;

		__global ulong* p0 = (__global ulong*)(scratchpad + (spAddr0 + sub * 8));
		__global ulong* p1 = (__global ulong*)(scratchpad + (spAddr1 + sub * 8));

		R[sub] ^= *p0;

		const int2 q = as_int2(*p1);
		fe[0] = load_F_E_groups(q.x, andMask, orMask1);
		fe[1] = load_F_E_groups(q.y, andMask, orMask2);

		barrier(CLK_LOCAL_MEM_FENCE);

		// TODO:
		//
		// 1) Compile with atomic_inc uncommented
		// 2) clrxdisasm -C randomx.bin > randomx.asm
		// 3) Replace GLOBAL_ATOMIC_ADD in randomx.asm with a call to JIT code (S_SWAPPC_B64 to call, S_SETPC_B64 to return)
		// 4) clrxasm randomx.asm -o randomx.bin
		// 5) ???
		// 6) PROFIT!!!

		atomic_inc(programs);

		mx ^= R[readReg2] ^ R[readReg3];
		mx &= CacheLineAlignMask;

		const ulong data = *(__global const ulong*)(dataset + ma + sub * 8);

		const ulong next_r = R[sub] ^ data;
		R[sub] = next_r;

		*p1 = next_r;
		*p0 = as_ulong(F[sub]) ^ as_ulong(E[sub]);

		uint tmp = ma;
		ma = mx;
		mx = tmp;

		spAddr0 = 0;
		spAddr1 = 0;
	}

	registers[sub] = R[sub];
	registers[sub +  8] = as_ulong(F[sub]) ^ as_ulong(E[sub]);
	registers[sub + 16] = as_ulong(E[sub]);
}
