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

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// PublicKeyType represents the public key algorithm for a given signature algorithm.
type PublicKeyType uint

const (
	RSA     PublicKeyType = iota // RSA public key
	ECDSA                        // ECDSA public key
	ED25519                      // ED25519 public key
)

// RSAKeySize represents the size of an RSA public key.
type RSAKeySize int

// AlgorithmDetails exposes relevant information for a given signature algorithm.
type AlgorithmDetails interface {
	// GetSignatureAlgorithm returns the algorithm registry.
	GetSignatureAlgorithm() v1.KnownSignatureAlgorithm

	// GetKeyType returns the public key algorithm for the given signature algorithm.
	GetKeyType() PublicKeyType

	// GetHashType returns the hash algorithm for a given signature algorithm.
	GetHashType() crypto.Hash

	// GetRSAKeySize returns the key size if the public key algorithm is RSA.
	// Otherwise, an error is returned.
	GetRSAKeySize() (RSAKeySize, error)

	// GetECDSACurve returns the curve if the public key algorithm is ECDSA.
	// Otherwise, an error is returned.
	GetECDSACurve() (*elliptic.Curve, error)

	checkKey(crypto.PublicKey) bool
	checkHash(crypto.Hash) bool
}

type algorithmDetailsImpl struct {
	knownAlgorithm v1.KnownSignatureAlgorithm
	keyType        PublicKeyType
	hashType       crypto.Hash
	extraKeyParams interface{}
	flagValue      string
}

func (a algorithmDetailsImpl) GetSignatureAlgorithm() v1.KnownSignatureAlgorithm {
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
		return 0, fmt.Errorf("unable to retrieve RSA key size for key type: %T", a.keyType)
	}
	rsaKeySize, ok := a.extraKeyParams.(RSAKeySize)
	if !ok {
		panic("unable to retrieve key size for RSA, malformed algorithm details?")
	}
	return rsaKeySize, nil
}

func (a algorithmDetailsImpl) GetECDSACurve() (*elliptic.Curve, error) {
	if a.keyType != ECDSA {
		return nil, fmt.Errorf("unable to retrieve ECDSA curve for key type: %T", a.keyType)
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
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_2048_SHA256, RSA, crypto.SHA256, RSAKeySize(2048), "rsa-sign-pkcs1-2048-sha256"},
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_3072_SHA256, RSA, crypto.SHA256, RSAKeySize(3072), "rsa-sign-pkcs1-3072-sha256"},
	{v1.KnownSignatureAlgorithm_RSA_SIGN_PKCS1_4096_SHA256, RSA, crypto.SHA256, RSAKeySize(4096), "rsa-sign-pkcs1-4096-sha256"},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_256_NISTP256, ECDSA, crypto.SHA256, elliptic.P256(), "ecdsa-sha2-256-nistp256"},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_384_NISTP384, ECDSA, crypto.SHA384, elliptic.P384(), "ecdsa-sha2-384-nistp384"},
	{v1.KnownSignatureAlgorithm_ECDSA_SHA2_512_NISTP521, ECDSA, crypto.SHA512, elliptic.P521(), "ecdsa-sha2-512-nistp521"},
	{v1.KnownSignatureAlgorithm_ED25519, ED25519, crypto.Hash(0), nil, "ed25519"},
	{v1.KnownSignatureAlgorithm_ED25519_PH, ED25519, crypto.Hash(0), nil, "ed25519-ph"},
}

// AlgorithmRegistryConfig represents a set of permitted algorithms for a given Sigstore service or component.
//
// Individual services may wish to restrict what algorithms are allowed to a subset of what is covered in the algorithm
// registry (represented by v1.KnownSignatureAlgorithm).
type AlgorithmRegistryConfig struct {
	permittedAlgorithms []AlgorithmDetails
}

// GetAlgorithmDetails retrieves a set of details for a given v1.KnownSignatureAlgorithm flag that allows users to
// introspect the public key algorithm, hash algorithm and more.
func GetAlgorithmDetails(knownSignatureAlgorithm v1.KnownSignatureAlgorithm) (AlgorithmDetails, error) {
	for _, detail := range algorithmDetails {
		if detail.knownAlgorithm == knownSignatureAlgorithm {
			return &detail, nil
		}
	}
	return nil, fmt.Errorf("could not find algorithm details for known signature algorithm: %s", knownSignatureAlgorithm)
}

// NewAlgorithmRegistryConfig creates a new AlgorithmRegistryConfig for a set of permitted signature algorithms.
func NewAlgorithmRegistryConfig(algorithmConfig []v1.KnownSignatureAlgorithm) (*AlgorithmRegistryConfig, error) {
	permittedAlgorithms := make([]AlgorithmDetails, 0, len(algorithmDetails))
	for _, algorithm := range algorithmConfig {
		a, err := GetAlgorithmDetails(algorithm)
		if err != nil {
			return nil, err
		}
		permittedAlgorithms = append(permittedAlgorithms, a)
	}
	return &AlgorithmRegistryConfig{permittedAlgorithms: permittedAlgorithms}, nil
}

// IsAlgorithmPermitted checks whether a given public key/hash algorithm combination is permitted by a registry config.
func (registryConfig AlgorithmRegistryConfig) IsAlgorithmPermitted(key crypto.PublicKey, hash crypto.Hash) error {
	for _, algorithm := range registryConfig.permittedAlgorithms {
		if algorithm.checkKey(key) && algorithm.checkHash(hash) {
			return nil
		}
	}
	return fmt.Errorf("signing algorithm not permitted: %T, %s", key, hash)
}

// FormatSignatureAlgorithmFlag formats a v1.KnownSignatureAlgorithm to a string that conforms to the conventions of CLI
// arguments that are used for Sigstore services.
func FormatSignatureAlgorithmFlag(algorithm v1.KnownSignatureAlgorithm) (*string, error) {
	for _, a := range algorithmDetails {
		if a.GetSignatureAlgorithm() == algorithm {
			return &a.flagValue, nil
		}
	}
	return nil, fmt.Errorf("could not find matching flag for signature algorithm: %s", algorithm)
}

// ParseSignatureAlgorithmFlag parses a string produced by FormatSignatureAlgorithmFlag and returns the corresponding
// v1.KnownSignatureAlgorithm value.
func ParseSignatureAlgorithmFlag(flag string) (v1.KnownSignatureAlgorithm, error) {
	for _, a := range algorithmDetails {
		if a.flagValue == flag {
			return a.GetSignatureAlgorithm(), nil
		}
	}
	return v1.KnownSignatureAlgorithm_KNOWN_SIGNATURE_ALGORITHM_UNSPECIFIED, fmt.Errorf("could not find matching signature algorithm for flag: %s", flag)
}
