/*
	Sheqi Zhang and Yulong Li 2019
	gm support addition/modification
	Modification: function and struct addition, sm2 oid addition
*/

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sm2"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

const ecPrivKeyVersion = 1

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return parseECPrivateKey(nil, der)
}

// MarshalECPrivateKey marshals an EC private key into ASN.1, DER format.
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	return marshalECPrivateKeyWithOID(key, oid)
}

// marshalECPrivateKey marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

// ParsePKCS8Sm2UnecryptedPrivateKey parses a sm2 Private Key Structure to DER format
func ParsePKCS8Sm2UnecryptedPrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	return ParseSm2PrivateKey(privKey.PrivateKey)
}

// gm support addition
// sm2PrivateKe structure
type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// gm support addition
// ParseSm2PrivateKey parses a sm2 private key
func ParseSm2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var privKey sm2PrivateKey

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := sm2.P256Sm2()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}

// WritePrivateKeytoMem converts a sm2 private key to PEM encoding
// It supports encrypted and unencrypted encoding
func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block

	der, err := MarshalSm2PrivateKey(key, pwd)
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalSm2PrivateKey converts a sm2 private key to DER format
// It supports encrypted and unencrypted encoding
func MarshalSm2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	if pwd == nil {
		return MarshalSm2UnecryptedPrivateKey(key)
	}
	return MarshalSm2EcryptedPrivateKey(key, pwd)
}

var (
	oidPBES1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	oidKEYMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// oidSM2 = asn1.ObjectIdentifier{1, 2, 156, 197, 1, 301}
)

// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm Pbes2Algorithms
	EncryptedData       []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params Pbes2Params
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Params struct {
	KeyDerivationFunc Pbes2KDfs // PBES2-KDFs
	EncryptionScheme  Pbes2Encs // PBES2-Encs
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2KDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params Pkdf2Params
}

type Pbes2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pkdf2Params struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}

// MarshalSm2EcryptedPrivateKey converts a sm2 private key to DER format with encryption
func MarshalSm2EcryptedPrivateKey(PrivKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	der, err := MarshalSm2UnecryptedPrivateKey(PrivKey)
	if err != nil {
		return nil, err
	}
	iter := 2048
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	rand.Reader.Read(salt)
	rand.Reader.Read(iv)
	key := pbkdf(pwd, salt, iter, 32, sha1.New) // 默认是SHA1
	padding := aes.BlockSize - len(der)%aes.BlockSize
	if padding > 0 {
		n := len(der)
		der = append(der, make([]byte, padding)...)
		for i := 0; i < padding; i++ {
			der[n+i] = byte(padding)
		}
	}
	encryptedKey := make([]byte, len(der))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, der)
	var algorithmIdentifier pkix.AlgorithmIdentifier
	algorithmIdentifier.Algorithm = oidKEYSHA1
	algorithmIdentifier.Parameters.Tag = 5
	algorithmIdentifier.Parameters.IsCompound = false
	algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	keyDerivationFunc := Pbes2KDfs{
		oidPBKDF2,
		Pkdf2Params{
			salt,
			iter,
			algorithmIdentifier,
		},
	}
	encryptionScheme := Pbes2Encs{
		oidAES256CBC,
		iv,
	}
	pbes2Algorithms := Pbes2Algorithms{
		oidPBES2,
		Pbes2Params{
			keyDerivationFunc,
			encryptionScheme,
		},
	}
	encryptedPkey := EncryptedPrivateKeyInfo{
		pbes2Algorithms,
		encryptedKey,
	}
	return asn1.Marshal(encryptedPkey)
}

// MarshalSm2UnecryptedPrivateKey converts a sm2 private key to DER format
func MarshalSm2UnecryptedPrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	var r pkcs8
	var priv sm2PrivateKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256SM2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = key.D.Bytes()
	r.Version = 0
	r.Algo = algo
	r.PrivateKey, _ = asn1.Marshal(priv)
	return asn1.Marshal(r)
}

// copy from crypto/pbkdf2.go
func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
