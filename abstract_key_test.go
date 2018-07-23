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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

const (
	JwsPayload = `{"key":"value"}`
)

func TestRsaPssVerifyWithAbstractVerifier(t *testing.T) {
	pvtKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if signer, err := NewSigner(PS256, pvtKey); err != nil {
		t.Errorf("error creating signer: %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestPssSignerVerifier(pvtKey, PS256, rsa.PSSSaltLengthAuto); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

func TestRsaPkcsVerifyWithAbstractVerifier(t *testing.T) {
	pvtKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if signer, err := NewSigner(RS256, pvtKey); err != nil {
		t.Errorf("error creating signer: %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestPkcs1_15SignerVerifier(pvtKey, RS256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

func TestRsaPssAbstractSignWithAbstractSigner(t *testing.T) {
	pvtKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if testSigner, err := newTestPssSignerVerifier(pvtKey, PS256, rsa.PSSSaltLengthAuto); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if signer, err := NewSigner(PS256, testSigner); err != nil {
		t.Fatalf("error creating Signer. %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestPssSignerVerifier(pvtKey, PS256, rsa.PSSSaltLengthAuto); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

func TestRsaPkcsAbstractSignWithAbstractSigner(t *testing.T) {
	pvtKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if testSigner, err := newTestPkcs1_15SignerVerifier(pvtKey, RS256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if signer, err := NewSigner(RS256, testSigner); err != nil {
		t.Fatalf("error creating Signer. %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestPkcs1_15SignerVerifier(pvtKey, RS256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

func TestEcdsaSignWithAbstractSigner(t *testing.T) {
	pvtKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if signer, err := NewSigner(ES256, pvtKey); err != nil {
		t.Fatalf("error creating Signer. %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestEcdsaSignerVerifier(pvtKey, ES256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

func TestEcdsaAbstractSignWithAbstractSigner(t *testing.T) {
	pvtKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if testSigner, err := newTestEcdsaSignerVerifier(pvtKey, ES256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if signer, err := NewSigner(ES256, testSigner); err != nil {
		t.Fatalf("error creating Signer. %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if verifier, err := newTestEcdsaSignerVerifier(pvtKey, ES256); err != nil {
		t.Fatalf("error creating testPssSignerVerifier. %q", err)
	} else if _, err := jws.Verify(verifier); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

type testSignerVerifier struct {
	algorithm  SignatureAlgorithm
	options    crypto.SignerOpts
	privateKey crypto.PrivateKey
}

func newTestPssSignerVerifier(
	key *rsa.PrivateKey,
	algorithm SignatureAlgorithm,
	saltLength int) (signerVerifier *testSignerVerifier, err error) {

	var hash crypto.Hash
	switch algorithm {
	case PS256:
		hash = crypto.SHA256
	case PS384:
		hash = crypto.SHA384
	case PS512:
		hash = crypto.SHA512
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return &testSignerVerifier{
		algorithm: algorithm,
		options: &rsa.PSSOptions{
			Hash:       hash,
			SaltLength: saltLength,
		},
		privateKey: key,
	}, nil
}

func newTestPkcs1_15SignerVerifier(key *rsa.PrivateKey, algorithm SignatureAlgorithm) (signerVerifier *testSignerVerifier, err error) {
	var hash crypto.Hash
	switch algorithm {
	case RS256:
		hash = crypto.SHA256
	case RS384:
		hash = crypto.SHA384
	case RS512:
		hash = crypto.SHA512
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return &testSignerVerifier{
		algorithm:  algorithm,
		options:    &testSignerOpts{hash: hash},
		privateKey: key,
	}, nil
}

func newTestEcdsaSignerVerifier(
	key *ecdsa.PrivateKey,
	algorithm SignatureAlgorithm) (signerVerifier *testSignerVerifier, err error) {

	var hash crypto.Hash
	switch algorithm {
	case ES256:
		hash = crypto.SHA256
	case ES384:
		hash = crypto.SHA384
	case ES512:
		hash = crypto.SHA512
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return &testSignerVerifier{
		algorithm:  algorithm,
		options:    &testSignerOpts{hash: hash},
		privateKey: key,
	}, nil
}

type testSignerOpts struct {
	hash crypto.Hash
}

func (ctx testSignerOpts) HashFunc() crypto.Hash {
	return ctx.hash
}

func (ctx *testSignerVerifier) SignPayload(payload []byte, algorithm SignatureAlgorithm) (signature []byte, err error) {
	hasher := ctx.options.HashFunc().New()
	if _, err = hasher.Write(payload); err == nil {
		digest := hasher.Sum(nil)
		switch k := ctx.privateKey.(type) {
		case *rsa.PrivateKey:
			signature, err = k.Sign(rand.Reader, digest, ctx.options)
		case *ecdsa.PrivateKey:
			signature, err = k.Sign(rand.Reader, digest, ctx.options)
			signature, err = asn1ToRS(signature)
		default:
			err = errors.New("Unsupported private key")
		}
	}
	return
}

func (ctx *testSignerVerifier) KeyID() string {
	return "fakeKey"
}

func (ctx *testSignerVerifier) Verify(payload []byte, signature []byte, alg SignatureAlgorithm) (err error) {
	hasher := ctx.options.HashFunc().New()
	if _, err = hasher.Write(payload); err == nil {
		digest := hasher.Sum(nil)
		switch alg {
		case PS256, PS384, PS512, RS256, RS384, RS512:
			switch opts := ctx.options.(type) {
			case *rsa.PSSOptions:
				err = rsa.VerifyPSS(
					ctx.privateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey),
					ctx.options.HashFunc(),
					digest,
					signature,
					opts)
			default:
				err = rsa.VerifyPKCS1v15(
					ctx.privateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey),
					ctx.options.HashFunc(),
					digest,
					signature)
			}
		case ES256, ES384, ES512:
			r := (&big.Int{}).SetBytes(signature[:len(signature)/2])
			s := (&big.Int{}).SetBytes(signature[len(signature)/2:])

			if !ecdsa.Verify(ctx.privateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey), digest, r, s) {
				err = errors.New("error failure to verify ecdsa signature")
			}
		default:
			err = ErrUnsupportedAlgorithm
		}
	}
	return
}

func asn1ToRS(asn1Sig []byte) (rsSig []byte, err error) {
	type ecSig struct {
		R, S *big.Int
	}
	unmarshalledSig := ecSig{}
	if _, err = asn1.Unmarshal(asn1Sig, &unmarshalledSig); err == nil {
		rsSig = append(unmarshalledSig.R.Bytes(), unmarshalledSig.S.Bytes()...)
	}
	return
}
