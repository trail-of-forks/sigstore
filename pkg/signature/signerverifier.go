//
// Copyright 2021 The Sigstore Authors.
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
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// SignerVerifier creates and verifies digital signatures over a message using a specified key pair
type SignerVerifier interface {
	Signer
	Verifier
}

// LoadSignerVerifier returns a signature.SignerVerifier based on the algorithm of the private key
// provided and the user's choice.
func LoadSignerVerifier(privateKey crypto.PrivateKey, hashFunc crypto.Hash, opts ...SignerVerifierOption) (SignerVerifier, error) {
	o := makeSignerVerifierOpts(opts...)

	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		if o.rsaPSSOptions != nil {
			return LoadRSAPSSSignerVerifier(pk, hashFunc, o.rsaPSSOptions)
		}
		return LoadRSAPKCS1v15SignerVerifier(pk, hashFunc)
	case *ecdsa.PrivateKey:
		return LoadECDSASignerVerifier(pk, hashFunc)
	case ed25519.PrivateKey:
		if o.useED25519ph {
			return LoadED25519phSignerVerifier(pk)
		}
		return LoadED25519SignerVerifier(pk)
	}
	return nil, errors.New("unsupported public key type")
}

// LoadSignerVerifierFromPEMFile returns a signature.SignerVerifier based on the algorithm of the private key
// in the file. The SignerVerifier will use the hash function specified when computing digests.
func LoadSignerVerifierFromPEMFile(path string, hashFunc crypto.Hash, pf cryptoutils.PassFunc, opts ...SignerVerifierOption) (SignerVerifier, error) {
	fileBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(fileBytes, pf)
	if err != nil {
		return nil, err
	}
	return LoadSignerVerifier(priv, hashFunc, opts...)
}
