package jose

import (
	"crypto"
	"io"
)

type SigningOptions uint

const (
	HashFunc SigningOptions = 1 + iota
)

type SignerOpts map[interface{}]interface{}

func (opts SignerOpts) HashFunc() crypto.Hash {
	if hf, ok := opts[HashFunc]; ok {
		if hf, ok := hf.(crypto.Hash); ok {
			return hf
		}
	}
	return crypto.Hash(0)
}

type AbstractSigner interface {
	KeyID() string
	RandReader() io.Reader
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

func (as *abstractSigner) signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error) {
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

	if signature.Signature, err = as.signer.Sign(as.signer.RandReader(), digest, signingOpts); err != nil {
		return signature, err
	}
	return signature, nil
}

type AbstractVerifier interface {
	Verify(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type abstractVerifier struct {
	abstractVerifier AbstractVerifier
}

func newAbstractVerifier(verifier AbstractVerifier) (payloadVerifier, error) {
	return &abstractVerifier{verifier}, nil
}

func (av *abstractVerifier) verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	return av.abstractVerifier.Verify(payload, signature, alg)
}
