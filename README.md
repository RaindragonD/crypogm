# 版本说明

本版本在Golang的crypto底层库修改x.509证书生成的相关代码，支持Hyperledger fabric以sm2算法为加密算法的X.509证书生成过程，支持生成公私钥及证书、存储获取秘钥和证书、验证签名和证书等功能。

使用注意事项
1. In common/tools/cryptogen/csp/generate.go, `GetECPublicKey(priv bccsp.Key)` is changed to `GetSM2PublicKey(priv bccsp.Key)` to generate `*sm2.PublicKey` typed varibale. To use `*ecdsa.PublicKey`, change `GetSM2PublicKey` back to `GetECPublicKey`
2. Case 30

# 代码注释规则

The following examples show three different comment template in our code.

	1. Case addition
	- explanation
		As long as you see the phrase "case addition," the following code is an extra case that we added for supporting Sm2.
	- example
		```
		/*
		Sheqi Zhang and Yulong Li 2019
		gm support addition/modification
		Case addition: (ks *fileBasedKeyStore) GetKey supports *sm2.PrivateKey
		*/
		```

	2. Struct/Const/Var defs
	- explanation
		As long as you see the phrase "struct def,” “Const defs,” or “Var defs,” the following struct/const/var definition is added for supporting Sm2.
	- example
		```
		/*
		Sheqi Zhang and Yulong Li 2019
		gm support addition/modification
		Struct defs: gmsm2KeyGenerator
		Case addition: (ks *fileBasedKeyStore) searchKeystoreForSKI supports
		  *sm2.PrivateKey
		*/
		```

	3. Funcs
	- explanation
		As long as you see the phrase "Funcs," the following function is wrote for supporting Sm2.
	- example
		```
		/*
		Sheqi Zhang and Yulong Li 2019
		gm support addition/modification
		Struct defs: gmsm2KeyGenerator
		Funcs: (sm *gmsm2KeyGenerator) KeyGen
		*/
		```
# Hyperledger Fabric 修改后支持国密的算法
	- bccsp/sw/conf.go
		`func (conf *config) setSecurityLevel(securityLevel int, hashFamily string)` supports `hashFamily == GMSM3`
	- bccsp/sw/fileks.go
		`func (ks *fileBasedKeyStore) GetKey(ski []byte)` supports `*sm2.PrivateKey` and `*sm2.PublicKey`
		`func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key)` supports and `*gmsm2PrivateKey ` and `*gmsm2PublicKey`
		`func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte)` supports `*sm2.PrivateKey`
	- bccsp/sw/keygen.go, keyimport.go, new.go
		supports all functions for sm2 keys
	- bccsp/utils/keys.go
		`func PrivateKeyToPEM(privateKey interface{}, pwd []byte)`, `func PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte)`, and `func DERToPrivateKey(der []byte)` supports `*sm2.PrivateKey`
		`func PublicKeyToPEM(publicKey interface{}, pwd []byte)`, `func PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte)`, `func PublicKeyToDER(publicKey interface{})`, and `func DERToPublicKey(raw []byte)` supports `*sm2.PublicKey`

# x509 library 修改后支持国密的方法
	- In x509.go
		```
		func marshalPublicKey(pub interface{})
		func ParsePKIXPublicKey(derBytes []byte)
		func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo)
		func checkSignature(algo SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey)
		func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{})
		func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{})
		func ParseCertificates(asn1Data []byte)
		func signingParamsForPublicKey(pub interface{}, requestedSigAlgo SignatureAlgorithm)
		```
	- In verify.go
		```
		func (c *Certificate) Verify(opts VerifyOptions)
		```

	- Note: Parameters `pub interface{}`, `publicKey crypto.PublicKey` etc. supports  `*sm2.PublicKey`. Certificate related functions supports sm2 signed x.509 certificates.