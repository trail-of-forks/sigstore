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
	// RSA public key
	RSA PublicKeyType = iota
	// ECDSA public key
	ECDSA
	// ED25519 public key
	ED25519
	// UNKNOWN public key
	UNKNOWN
)

// RSAKeySize represents the size of an RSA public key in bits.
type RSAKeySize int

type PublicKeyId struct {
	publicKeyType PublicKeyType
	rsaKeySize    RSAKeySize
	ecdsaCurve    elliptic.Curve
}

func RSAPublicKeyId(keySize RSAKeySize) PublicKeyId {
	return PublicKeyId{RSA, keySize, nil}
}

func ECDSAPublicKeyId(curve elliptic.Curve) PublicKeyId {
	return PublicKeyId{ECDSA, 0, curve}
}

func ED25519PublicKeyId() PublicKeyId {
	return PublicKeyId{ED25519, 0, nil}
}

func PublicKeyIdFromPublicKey(key crypto.PublicKey) (PublicKeyId, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return RSAPublicKeyId(RSAKeySize(key.N.BitLen())), nil
	case *ecdsa.PublicKey:
		return ECDSAPublicKeyId(key.Curve), nil
	case ed25519.PublicKey:
		return ED25519PublicKeyId(), nil
	default:
		return PublicKeyId{}, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// AlgorithmDetails exposes relevant information for a given signature algorithm.
type AlgorithmDetails interface {
	// GetSignatureAlgorithm returns the algorithm registry.
	GetSignatureAlgorithm() v1.PublicKeyDetails

	// GetPublicKeyId returns the public key id for the given signature algorithm.
	GetPublicKeyId() PublicKeyId

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

	// IsValidPrivateKey checks if the private key matches the signature algorithm.
	IsValidPrivateKey(crypto.PrivateKey) (bool, error)

	// IsValidPublicKey checks if the public key matches the signature algorithm.
	IsValidPublicKey(crypto.PublicKey) (bool, error)
}

type algorithmDetailsImpl struct {
	// knownAlgorithm is the signature algorithm that the following details refer to.
	knownAlgorithm v1.PublicKeyDetails

	// keyId is an id to identify the public key.
	keyId PublicKeyId

	// hashType is the hash algorithm being used.
	hashType crypto.Hash

	// flagValue is a string representation of the signature algorithm that follows the naming conventions of CLI
	// arguments that are used for Sigstore services.
	flagValue string
}

func (a algorithmDetailsImpl) GetSignatureAlgorithm() v1.PublicKeyDetails {
	return a.knownAlgorithm
}

func (a algorithmDetailsImpl) GetPublicKeyId() PublicKeyId {
	return a.keyId
}

func (a algorithmDetailsImpl) GetKeyType() PublicKeyType {
	return a.keyId.publicKeyType
}

func (a algorithmDetailsImpl) GetHashType() crypto.Hash {
	return a.hashType
}

func (a algorithmDetailsImpl) GetRSAKeySize() (RSAKeySize, error) {
	if a.keyId.publicKeyType != RSA {
		return 0, fmt.Errorf("unable to retrieve RSA key size for key type: %T", a.keyId.publicKeyType)
	}
	return a.keyId.rsaKeySize, nil
}

func (a algorithmDetailsImpl) GetECDSACurve() (*elliptic.Curve, error) {
	if a.keyId.publicKeyType != ECDSA {
		return nil, fmt.Errorf("unable to retrieve ECDSA curve for key type: %T", a.keyId.publicKeyType)
	}
	return &a.keyId.ecdsaCurve, nil
}

func (a algorithmDetailsImpl) IsValidPrivateKey(privKey crypto.PrivateKey) (bool, error) {
	switch a.keyId.publicKeyType {
	case RSA:
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return false, nil
		}
		keySize, err := a.GetRSAKeySize()
		if err != nil {
			return false, err
		}
		return rsaKey.Size()*8 == int(keySize), nil
	case ECDSA:
		ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return false, nil
		}
		curve, err := a.GetECDSACurve()
		if err != nil {
			return false, err
		}
		return ecdsaKey.Curve == *curve, nil
	case ED25519:
		_, ok := privKey.(ed25519.PrivateKey)
		return ok, nil
	}
	return false, fmt.Errorf("unrecognized key type: %T", a.keyId.publicKeyType)
}

func (a algorithmDetailsImpl) IsValidPublicKey(pubKey crypto.PublicKey) (bool, error) {
	switch a.keyId.publicKeyType {
	case RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		keySize, err := a.GetRSAKeySize()
		if err != nil {
			return false, err
		}
		return rsaKey.Size()*8 == int(keySize), nil
	case ECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		curve, err := a.GetECDSACurve()
		if err != nil {
			return false, err
		}
		return ecdsaKey.Curve == *curve, nil
	case ED25519:
		_, ok := pubKey.(ed25519.PublicKey)
		return ok, nil
	}
	return false, fmt.Errorf("unrecognized key type: %T", a.keyId.publicKeyType)
}

func (a algorithmDetailsImpl) checkHash(hashType crypto.Hash) bool {
	return a.hashType == hashType
}

// Note that deprecated options in PublicKeyDetails are not included in this
// list, including PKCS1v1.5 encoded RSA. Refer to the v1.PublicKeyDetails enum
// for more details.
var supportedAlgorithms = []algorithmDetailsImpl{
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, RSAPublicKeyId(2048), crypto.SHA256, "rsa-sign-pkcs1-2048-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, RSAPublicKeyId(3072), crypto.SHA256, "rsa-sign-pkcs1-3072-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, RSAPublicKeyId(4096), crypto.SHA256, "rsa-sign-pkcs1-4096-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256, RSAPublicKeyId(2048), crypto.SHA256, "rsa-sign-pss-2048-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_3072_SHA256, RSAPublicKeyId(3072), crypto.SHA256, "rsa-sign-pss-3072-sha256"},
	{v1.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256, RSAPublicKeyId(4096), crypto.SHA256, "rsa-sign-pss-4096-sha256"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, ECDSAPublicKeyId(elliptic.P256()), crypto.SHA256, "ecdsa-sha2-256-nistp256"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, ECDSAPublicKeyId(elliptic.P384()), crypto.SHA384, "ecdsa-sha2-384-nistp384"},
	{v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, ECDSAPublicKeyId(elliptic.P521()), crypto.SHA512, "ecdsa-sha2-512-nistp521"},
	{v1.PublicKeyDetails_PKIX_ED25519, ED25519PublicKeyId(), crypto.SHA512, "ed25519"},
	{v1.PublicKeyDetails_PKIX_ED25519_PH, ED25519PublicKeyId(), crypto.SHA512, "ed25519-ph"},
}

// AlgorithmRegistryConfig represents a set of permitted algorithms for a given Sigstore service or component.
//
// Individual services may wish to restrict what algorithms are allowed to a subset of what is covered in the algorithm
// registry (represented by v1.PublicKeyDetails).
type AlgorithmRegistryConfig struct {
	permittedAlgorithms []algorithmDetailsImpl
}

// GetAlgorithmDetails retrieves a set of details for a given v1.PublicKeyDetails flag that allows users to
// introspect the public key algorithm, hash algorithm and more.
func GetAlgorithmDetails(knownSignatureAlgorithm v1.PublicKeyDetails) (AlgorithmDetails, error) {
	return getAlgorithmDetails(knownSignatureAlgorithm)
}

// GetAlgorithmDetailsForPublicKey retrieves a set of details that are valid for a given public key.
func GetAlgorithmDetailsForPublicKey(key crypto.PublicKey) ([]AlgorithmDetails, error) {
	algorithmDetails := []AlgorithmDetails{}
	for _, detail := range supportedAlgorithms {
		valid, err := detail.IsValidPublicKey(key)
		if err != nil {
			return nil, err
		}
		if valid {
			algorithmDetails = append(algorithmDetails, detail)
		}
	}
	return algorithmDetails, nil
}

func getAlgorithmDetails(knownSignatureAlgorithm v1.PublicKeyDetails) (*algorithmDetailsImpl, error) {
	for _, detail := range supportedAlgorithms {
		if detail.knownAlgorithm == knownSignatureAlgorithm {
			return &detail, nil
		}
	}
	return nil, fmt.Errorf("could not find algorithm details for known signature algorithm: %s", knownSignatureAlgorithm)
}

// NewAlgorithmRegistryConfig creates a new AlgorithmRegistryConfig for a set of permitted signature algorithms.
func NewAlgorithmRegistryConfig(algorithmConfig []v1.PublicKeyDetails) (*AlgorithmRegistryConfig, error) {
	permittedAlgorithms := make([]algorithmDetailsImpl, 0, len(supportedAlgorithms))
	for _, algorithm := range algorithmConfig {
		a, err := getAlgorithmDetails(algorithm)
		if err != nil {
			return nil, err
		}
		permittedAlgorithms = append(permittedAlgorithms, *a)
	}
	return &AlgorithmRegistryConfig{permittedAlgorithms: permittedAlgorithms}, nil
}

// IsAlgorithmPermitted checks whether a given public key/hash algorithm combination is permitted by a registry config.
func (registryConfig AlgorithmRegistryConfig) IsAlgorithmPermitted(key crypto.PublicKey, hash crypto.Hash) (bool, error) {
	for _, algorithm := range registryConfig.permittedAlgorithms {
		keyMatch, err := algorithm.IsValidPublicKey(key)
		if err != nil {
			return false, err
		}
		if keyMatch && algorithm.checkHash(hash) {
			return true, nil
		}
	}
	return false, nil
}

// FormatSignatureAlgorithmFlag formats a v1.PublicKeyDetails to a string that conforms to the naming conventions
// of CLI arguments that are used for Sigstore services.
func FormatSignatureAlgorithmFlag(algorithm v1.PublicKeyDetails) (string, error) {
	for _, a := range supportedAlgorithms {
		if a.knownAlgorithm == algorithm {
			return a.flagValue, nil
		}
	}
	return "", fmt.Errorf("could not find matching flag for signature algorithm: %s", algorithm)
}

// ParseSignatureAlgorithmFlag parses a string produced by FormatSignatureAlgorithmFlag and returns the corresponding
// v1.PublicKeyDetails value.
func ParseSignatureAlgorithmFlag(flag string) (v1.PublicKeyDetails, error) {
	for _, a := range supportedAlgorithms {
		if a.flagValue == flag {
			return a.knownAlgorithm, nil
		}
	}
	return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, fmt.Errorf("could not find matching signature algorithm for flag: %s", flag)
}
