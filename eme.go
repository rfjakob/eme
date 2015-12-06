// EME (ECB-Mix-ECB) is a wide-block encryption mode presented in the 2003 paper
// "A Parallelizable Enciphering Mode" by Halevi and Rogaway.
// This is an implementation of EME in Go.
package eme

import (
	"crypto/cipher"
	"log"
)

const (
	directionEncrypt = iota
	directionDecrypt
)

// multByTwo - GF multiplication as specified in the EME-32 draft
func multByTwo(out []byte, in []byte) {
	if len(in) != 16 {
		panic("len must be 16")
	}
	tmp := make([]byte, 16)

	tmp[0] = 2 * in[0]
	if in[15] >= 128 {
		tmp[0] = tmp[0] ^ 135
	}
	for j := 1; j < 16; j++ {
		tmp[j] = 2 * in[j]
		if in[j-1] >= 128 {
			tmp[j] += 1
		}
	}
	copy(out, tmp)
}

func xorBlocks(out []byte, in1 []byte, in2 []byte) {
	if len(in1) != len(in2) {
		log.Panicf("len(in1)=%d is not equal to len(in2)=%d", len(in1), len(in2))
	}

	for i := range in1 {
		out[i] = in1[i] ^ in2[i]
	}
}

// bcTransform - encrypt or decrypt (according to "direction") using block
// cipher "bc"
func bcTransform(dst []byte, src []byte, direction int, bc cipher.Block) {
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

func tabulateL(eZero []byte, m int) ([][]byte) {
	LTable := make([][]byte, m)
	buf := make([]byte, len(LTable)*16)
	Li := make([]byte, 16)
	copy(Li, eZero)
	for i := 0; i < len(LTable); i++ {
		multByTwo(Li, Li)
		LTable[i] = buf[i*16:(i+1)*16]
		copy(LTable[i], Li)
	}
	return LTable
}

// EMETransform - EME-encrypt or EME-decrypt (according to "direction") the data
// in "P" with the block ciper "bc" under tweak "T".
// The result is returned in a freshly allocated slice.
func EMETransform(bc cipher.Block, T []byte, P []byte, direction int) (C []byte) {
	C = make([]byte, 512)
	m := len(P) / bc.BlockSize()

	if m == 0 || m >= bc.BlockSize()*8 {
		log.Panicf("EME operates on 1-%d block-cipher blocks", bc.BlockSize()*8)
	}

	/* set L = 2*AESenc(K; 0) */
	eZero := make([]byte, 16)
	bc.Encrypt(eZero, eZero)

	LTable := tabulateL(eZero, m)

	PPj := make([]byte, 16)
	for j := 0; j < m; j++ {
		Pj := P[j*16 : (j+1)*16]
		/* PPj = 2**(j-1)*L xor Pj */
		xorBlocks(PPj, Pj, LTable[j])
		/* PPPj = AESenc(K; PPj) */
		bcTransform(C[j*16:(j+1)*16], PPj, direction, bc)
	}

	/* MP =(xorSum PPPj) xor T */
	MP := make([]byte, 16)
	xorBlocks(MP, C[0:16], T)
	for j := 1; j < m; j++ {
		xorBlocks(MP, MP, C[j*16:(j+1)*16])
	}

	/* MC = AESenc(K; MP) */
	MC := make([]byte, 16)
	bcTransform(MC, MP, direction, bc)

	/* M = MP xor MC */
	M := make([]byte, 16)
	xorBlocks(M, MP, MC)
	CCCj := make([]byte, 16)
	for j := 1; j < m; j++ {
		multByTwo(M, M)
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

	for j := 0; j < m; j++ {
		/* CCj = AES-enc(K; CCCj) */
		bcTransform(C[j*16:(j+1)*16], C[j*16:(j+1)*16], direction, bc)
		/* Cj = 2**(j-1)*L xor CCj */
		xorBlocks(C[j*16:(j+1)*16], C[j*16:(j+1)*16], LTable[j])
	}

	return C
}
