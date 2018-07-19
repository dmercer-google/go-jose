/*-
 * Copyright 2018 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto"
	"io"
)

type SigningOptions uint

const (
	// Indicates the hash function used to generate the gigest of a message.  The value must be a member of crypto.Hash
	HashFunc SigningOptions = iota
)

// A map of key value pairs used to pass signing parameters to the underlying signing implementation
type SignerOpts map[SigningOptions]interface{}

// Implemented such that SignerOpts implements crypto.SignerOpts
func (opts SignerOpts) HashFunc() crypto.Hash {
	if hf, ok := opts[HashFunc]; ok {
		if hf, ok := hf.(crypto.Hash); ok && hf.Available() {
			return hf
		}
	}
	panic("square/go-jose: hash function is not specified or is not supported by the runtime.")
}

// When implemented, allows keys that are not natively supported by Golang or go-jose to be used for signing operations.
// Examples of such keys include those implemented by PKCS11 providers, native keys where a non native entropy source
// must be used to generate signatures, etc.
type AbstractSigner interface {
	// The Key Identifier of the key to be inserted into the `kid` claim of the jose header.
	KeyID() string

	// The random number generator to be used as the entropy source for signing operations.
	// Unless an external source of entropy is to be used this function should return rand.Reader.
	RandReader() io.Reader

	// Signs the digest of the message.
	Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
}

type abstractSigner struct {
	signer AbstractSigner
}

func newAbstractSigner(sigAlg SignatureAlgorithm, signer AbstractSigner) (recipientSigInfo, error) {
	return recipientSigInfo{
		sigAlg: sigAlg,
		keyID:  signer.KeyID(),
		signer: &abstractSigner{signer: signer},
	}, nil
}

func (ctx *abstractSigner) signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error) {
	signature := Signature{protected: &rawHeader{}}
	var err error
	signingOpts := SignerOpts{}
	switch alg {
	case HS256, RS256, ES256, PS256:
		signingOpts[HashFunc] = crypto.SHA256
	case HS384, RS384, ES384, PS384:
		signingOpts[HashFunc] = crypto.SHA384
	case HS512, RS512, ES512, PS512:
		signingOpts[HashFunc] = crypto.SHA512
	default:
		return signature, ErrUnsupportedAlgorithm
	}
	hasher := signingOpts.HashFunc().New()
	if _, err = hasher.Write(payload); err != nil {
		return signature, err
	}
	digest := hasher.Sum(nil)

	if signature.Signature, err = ctx.signer.Sign(ctx.signer.RandReader(), digest, signingOpts); err != nil {
		return signature, err
	}
	return signature, nil
}

// When implemented, allows keys not natively supported by Golang or go-jose to be used to verify signatures.
// Examples of such keys include those implemented by PKCS11 providers, etc.
type AbstractVerifier interface {
	Verify(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type abstractVerifier struct {
	abstractVerifier AbstractVerifier
}

func newAbstractVerifier(verifier AbstractVerifier) (payloadVerifier, error) {
	return &abstractVerifier{verifier}, nil
}

func (ctx *abstractVerifier) verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	return ctx.abstractVerifier.Verify(payload, signature, alg)
}
