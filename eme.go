package eme

import (
	"crypto/aes"
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

func xorBlocks(in1 []byte, in2 []byte) (out []byte) {
	if len(in1) != len(in2) {
		log.Panicf("len(in1)=%d is not equal to len(in2)=%d", len(in1), len(in2))
	}

	out = make([]byte, len(in1))
	for i := range in1 {
		out[i] = in1[i] ^ in2[i]
	}
	return out
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

func TransformEME32(K []byte, T []byte, P []byte, direction int) (C []byte) {
	aesCipher, err := aes.NewCipher(K)
	if err != nil {
		panic(err)
	}

	C = make([]byte, 512)

	/* set L = 2*AESenc(K; 0) */
	zero := make([]byte, 16)
	aesCipher.Encrypt(zero, zero)
	L := multByTwo(zero)

	for j := 0; j < 32; j++ {
		Pj := P[j*16 : (j+1)*16]
		/* PPj = 2**(j-1)*L xor Pj */
		PPj := xorBlocks(Pj, L)
		/* PPPj = AESenc(K; PPj) */
		transformAES(C[j*16:(j+1)*16], PPj, direction, aesCipher)
		L = multByTwo(L)
	}

	/* MP =(xorSum PPPj) xor T */
	MP := xorBlocks(C[0:16], T)
	for j := 1; j < 32; j++ {
		MP = xorBlocks(MP, C[j*16:(j+1)*16])
	}

	/* MC = AESenc(K; MP) */
	MC := make([]byte, 16)
	transformAES(MC, MP, direction, aesCipher)

	/* M = MP xor MC */
	M := xorBlocks(MP, MC)

	for j := 1; j < 32; j++ {
		M = multByTwo(M)
		/* CCCj = 2**(j-1)*M xor PPPj */
		CCCj := xorBlocks(C[j*16:(j+1)*16], M)
		copy(C[j*16:(j+1)*16], CCCj)
	}

	/* CCC1 = (xorSum CCCj) xor T xor MC */
	CCC1 := xorBlocks(MC, T)
	for j := 1; j < 32; j++ {
		CCC1 = xorBlocks(CCC1, C[j*16:(j+1)*16])
	}
	copy(C[0:16], CCC1)

	/* reset L = 2*AESenc(K; 0) */
	L = multByTwo(zero)
	for j := 0; j < 32; j++ {
		/* CCj = AES-enc(K; CCCj) */
		transformAES(C[j*16:(j+1)*16], C[j*16:(j+1)*16], direction, aesCipher)
		/* Cj = 2**(j-1)*L xor CCj */
		Cj := xorBlocks(C[j*16:(j+1)*16], L)
		copy(C[j*16:(j+1)*16], Cj)
		L = multByTwo(L)
	}

	return C
}
