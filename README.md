# 版本说明

本版本在Golang的crypto底层库修改x.509证书生成的相关代码，支持Hyperledger fabric以sm2算法为加密算法的X.509证书生成过程，支持生成公私钥及证书、存储获取秘钥和证书、验证签名和证书等功能。

## 使用注意事项
1. In common/tools/cryptogen/csp/generate.go, `GetECPublicKey(priv bccsp.Key)` is changed to `GetSM2PublicKey(priv bccsp.Key)` to generate `*sm2.PublicKey` typed varibale. To use `*ecdsa.PublicKey`, change `GetSM2PublicKey` back to `GetECPublicKey`
2. In $GOROOT/src/crypto/x509/x509.go, `func parseCertificate(in *certificate)` doesn't support `case 30` when parsing `TBSCertificate.Extensions`.

# 使用GMSSL测试支持国密的x.509证书生成
1. 在deepchain目录下生成cryptogen binary
	```shell
	make cryptogen
	.build/bin/cryptogen generate
	```
	在cryptogen-config找到任意一组私钥和证书进行如下测试，如：
	```shell
	cd crypto-config/ordererOrganizations/example.com/ca
	```
2. 生成公钥
	```shell
	gmssl sm2 -in [private_key_PEM] -inform PEM -pubout -text -out ~/Desktop/pkey.pem
	```
3. 私钥签名
	创建测试文件 test.md
	```shell
	echo "test" > test.md
	```
	使用私钥生成签名
	```shell
	gmssl sm2utl -sign -in test.md -inkey [private_key_PEM] -out sigfile.sig -id 1234567812345678
	```
4. 公钥验签
	```shell
	gmssl sm2utl -verify -in test.md -pubin -inkey ~/Desktop/pkey.pem -sigfile sigfile.sig -id 1234567812345678
	```
	应显示：
	```shell
	Signature Verification Successful
	```
5. 查看证书内容
	```shell
	gmssl x509 -in [cert_PEM] -text -noout
	```
# Hyperledger Fabric 修改后支持国密的算法
- bccsp/sw/conf.go
	```go
	func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) 
	```
	supports `hashFamily == GMSM3`
- bccsp/sw/fileks.go
	```go
	func (ks *fileBasedKeyStore) GetKey(ski []byte) 
	func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key)
	```
	supports `*sm2.PrivateKey` and `*sm2.PublicKey`
	```go
	func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte) 
	```
	supports `*sm2.PrivateKey`
- bccsp/sw/keygen.go, keyimport.go, new.go
	supports all functions for sm2 keys
- bccsp/utils/keys.go
	```go
	func PrivateKeyToPEM(privateKey interface{}, pwd []byte)
	func PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte)
	func DERToPrivateKey(der []byte) 
	```
	supports `*sm2.PrivateKey`
	```go
	func PublicKeyToPEM(publicKey interface{}, pwd []byte)
	func PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte)
	func PublicKeyToDER(publicKey interface{}), and func DERToPublicKey(raw []byte) 
	```
	supports `*sm2.PublicKey`
# x509 library 修改后支持国密的方法
- In x509.go
	```go
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
	```go
	func (c *Certificate) Verify(opts VerifyOptions)
	```
- Note: Parameters `pub interface{}`, `publicKey crypto.PublicKey` etc. supports  `*sm2.PublicKey`. Certificate related functions supports sm2 signed x.509 certificates.
# 代码注释规则
The following examples show three different comment template in our code.
1. "Case addition" means that the following code is an extra case added to support gm.
- example
	```go
	/*
	Sheqi Zhang and Yulong Li 2019
	gm support addition/modification
	Case addition: (ks *fileBasedKeyStore) GetKey supports *sm2.PrivateKey
	*/
	```
2. "Struct/Const/Var defs" means that the following struct/const/var definitions are added to support gm.
- example
	```go
	/*
	Sheqi Zhang and Yulong Li 2019
	gm support addition/modification
	Struct defs: gmsm2KeyGenerator
	Case addition: (ks *fileBasedKeyStore) searchKeystoreForSKI supports
		*sm2.PrivateKey
	*/
	```
3. "Funcs" means that the following function is added to support gm.
- example
	```go
	/*
	Sheqi Zhang and Yulong Li 2019
	gm support addition/modification
	Struct defs: gmsm2KeyGenerator
	Funcs: (sm *gmsm2KeyGenerator) KeyGen
	*/
	```