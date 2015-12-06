package eme

import (
	"crypto/cipher"
	"log"
)

const (
	directionEncrypt = iota
	directionDecrypt
)

func multByTwo(in []byte) (out []byte) {
	if len(in) != 16 {
		panic("len must be 16")
	}
	out = make([]byte, 16)

	out[0] = 2 * in[0]
	if in[15] >= 128 {
		out[0] = out[0] ^ 135
	}
	for j := 1; j < 16; j++ {
		out[j] = 2 * in[j]
		if in[j-1] >= 128 {
			out[j] += 1
		}
	}
	return out
}

func xorBlocks(out []byte, in1 []byte, in2 []byte) {
	if len(in1) != len(in2) {
		log.Panicf("len(in1)=%d is not equal to len(in2)=%d", len(in1), len(in2))
	}

	for i := range in1 {
		out[i] = in1[i] ^ in2[i]
	}
}

func transformAES(dst []byte, src []byte, direction int, bc cipher.Block) {
	if direction == directionEncrypt {
		bc.Encrypt(dst, src)
		return
	} else if direction == directionDecrypt {
		bc.Decrypt(dst, src)
		return
	} else {
		log.Panicf("unknown direction %d", direction)
	}
}

func TransformEME32(bc cipher.Block, T []byte, P []byte, direction int) (C []byte) {
	C = make([]byte, 512)
	m := len(P) / bc.BlockSize()

	if m == 0 || m >= bc.BlockSize()*8 {
		log.Panicf("EME operates on 1-%d block-cipher blocks", bc.BlockSize()*8)
	}

	/* set L = 2*AESenc(K; 0) */
	zero := make([]byte, 16)
	bc.Encrypt(zero, zero)
	L := multByTwo(zero)

	PPj := make([]byte, 16)
	for j := 0; j < m; j++ {
		Pj := P[j*16 : (j+1)*16]
		/* PPj = 2**(j-1)*L xor Pj */
		xorBlocks(PPj, Pj, L)
		/* PPPj = AESenc(K; PPj) */
		transformAES(C[j*16:(j+1)*16], PPj, direction, bc)
		L = multByTwo(L)
	}

	/* MP =(xorSum PPPj) xor T */
	MP := make([]byte, 16)
	xorBlocks(MP, C[0:16], T)
	for j := 1; j < m; j++ {
		xorBlocks(MP, MP, C[j*16:(j+1)*16])
	}

	/* MC = AESenc(K; MP) */
	MC := make([]byte, 16)
	transformAES(MC, MP, direction, bc)

	/* M = MP xor MC */
	M := make([]byte, 16)
	xorBlocks(M, MP, MC)
	CCCj := make([]byte, 16)
	for j := 1; j < m; j++ {
		M = multByTwo(M)
		/* CCCj = 2**(j-1)*M xor PPPj */
		xorBlocks(CCCj, C[j*16:(j+1)*16], M)
		copy(C[j*16:(j+1)*16], CCCj)
	}

	/* CCC1 = (xorSum CCCj) xor T xor MC */
	CCC1 := make([]byte, 16)
	xorBlocks(CCC1, MC, T)
	for j := 1; j < m; j++ {
		xorBlocks(CCC1, CCC1, C[j*16:(j+1)*16])
	}
	copy(C[0:16], CCC1)

	/* reset L = 2*AESenc(K; 0) */
	L = multByTwo(zero)
	for j := 0; j < m; j++ {
		/* CCj = AES-enc(K; CCCj) */
		transformAES(C[j*16:(j+1)*16], C[j*16:(j+1)*16], direction, bc)
		/* Cj = 2**(j-1)*L xor CCj */
		xorBlocks(C[j*16:(j+1)*16], C[j*16:(j+1)*16], L)
		L = multByTwo(L)
	}

	return C
}
