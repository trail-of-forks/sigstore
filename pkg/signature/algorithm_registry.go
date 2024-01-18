//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type PublicKeyType uint

const (
	RSA PublicKeyType = iota
	ECDSA
	ED25519
)

type RSAKeySize int

type AlgorithmDetails interface {
	GetKnownAlgorithm() v1.KnownSignatureAlgorithm
	GetKeyType() PublicKeyType
	GetHashType() crypto.Hash
	GetRSAKeySize() (RSAKeySize, error)
	GetECDSACurve() (*elliptic.Curve, error)
	checkKey(crypto.PublicKey) bool
	checkHash(crypto.Hash) bool
}

type algorithmDetailsImpl struct {
	knownAlgorithm v1.KnownSignatureAlgorithm
	keyType        PublicKeyType
	hashType       crypto.Hash
	extraKeyParams interface{}
}

func (a algorithmDetailsImpl) GetKnownAlgorithm() v1.KnownSignatureAlgorithm {
	return a.knownAlgorithm
}

func (a algorithmDetailsImpl) GetKeyType() PublicKeyType {
	return a.keyType
}

func (a algorithmDetailsImpl) GetHashType() crypto.Hash {
	return a.hashType
}

func (a algorithmDetailsImpl) GetRSAKeySize() (RSAKeySize, error) {
	if a.keyType != RSA {
		return 0, fmt.Errorf("unable to retrieve RSA key size for key type: %s", a.keyType)
	}
	rsaKeySize, ok := a.extraKeyParams.(RSAKeySize)
	if !ok {
		panic("unable to retrieve key size for RSA, malformed algorithm details?")
	}
	return rsaKeySize, nil
}

func (a algorithmDetailsImpl) GetECDSACurve() (*elliptic.Curve, error) {
	if a.keyType != ECDSA {
		return nil, fmt.Errorf("unable to retrieve ECDSA curve for key type: %s", a.keyType)
	}
	ecdsaCurve, ok := a.extraKeyParams.(elliptic.Curve)
	if !ok {
		panic("unable to retrieve curve for ECDSA, malformed algorithm details?")
	}
	return &ecdsaCurve, nil
}

func (a algorithmDetailsImpl) checkKey(pubKey crypto.PublicKey) bool {
	switch a.keyType {
	case RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		keySize, err := a.GetRSAKeySize()
		if err != nil {
			panic(err)
		}
		return rsaKey.Size() == int(keySize)
	case ECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		curve, err := a.GetECDSACurve()
		if err != nil {
			panic(err)
		}
		return ecdsaKey.Curve == *curve
	case ED25519:
		_, ok := pubKey.(*ed25519.PublicKey)
		return ok
	}
	panic("unreachable")
}

func (a algorithmDetailsImpl) checkHash(hashType crypto.Hash) bool {
	return a.hashType == hashType
}

var algorithmDetails = []algorithmDetailsImpl{
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_2048_SHA256, RSA, crypto.SHA256, RSAKeySize(2048)},
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_3072_SHA256, RSA, crypto.SHA256, RSAKeySize(3072)},
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_4096_SHA256, RSA, crypto.SHA256, RSAKeySize(4096)},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_256_NISTP256, ECDSA, crypto.SHA256, elliptic.P256()},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_384_NISTP384, ECDSA, crypto.SHA384, elliptic.P384()},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_512_NISTP521, ECDSA, crypto.SHA512, elliptic.P521()},
	{v1.KnownSignatureAlgorithm_ED25519, ED25519, crypto.Hash(0), nil},
	{v1.KnownSignatureAlgorithm_ED25519_PH, ED25519, crypto.Hash(0), nil},
}

type AlgorithmRegistry struct {
	permittedAlgorithms []AlgorithmDetails
}

func GetAlgorithmDetails(knownSignatureAlgorithm v1.KnownSignatureAlgorithm) (AlgorithmDetails, error) {
	for _, detail := range algorithmDetails {
		if detail.knownAlgorithm == knownSignatureAlgorithm {
			return &detail, nil
		}
	}
	return nil, fmt.Errorf("could not find algorithm details for known signature algorithm: %s", knownSignatureAlgorithm)
}

func NewAlgorithmRegistry(algorithmConfig []v1.KnownSignatureAlgorithm) (*AlgorithmRegistry, error) {
	var permittedAlgorithms []AlgorithmDetails
	for _, algorithm := range algorithmConfig {
		a, err := GetAlgorithmDetails(algorithm)
		if err != nil {
			return nil, err
		}
		permittedAlgorithms = append(permittedAlgorithms, a)
	}
	return &AlgorithmRegistry{permittedAlgorithms: permittedAlgorithms}, nil
}

func (registry AlgorithmRegistry) CheckAlgorithm(key crypto.PublicKey, hash crypto.Hash) error {
	for _, algorithm := range registry.permittedAlgorithms {
		if algorithm.checkKey(key) && algorithm.checkHash(hash) {
			return nil
		}
	}
	return fmt.Errorf("signing algorithm not permitted: %T, %s", key, hash)
}
