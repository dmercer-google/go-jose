package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

func TestSignerWithAbstractSigner(t *testing.T) {
	pvtKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if signer, err := NewSigner(ES256, &fakeGenericKey{privateKey: pvtKey}); err != nil {
		t.Errorf("error creating signer: %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if compactSerialized, err := jws.CompactSerialize(); err != nil {
		t.Errorf("error compact serializing: %q", err)
	} else if jws, err := ParseSigned(compactSerialized); err != nil {
		t.Errorf("error parsing token: %q", err)
	} else if _, err := jws.Verify(pvtKey.Public()); err != nil {
		t.Fatalf("error Verifying token: %s", err)
	}
}

func TestVerifyWithAbstractVerifier(t *testing.T) {
	pvtKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if signer, err := NewSigner(ES256, pvtKey); err != nil {
		t.Errorf("error creating signer: %q", err)
	} else if jws, err := signer.Sign([]byte("test")); err != nil {
		t.Errorf("error signing: %q", err)
	} else if _, err := jws.Verify(&fakeGenericKey{pvtKey}); err != nil {
		t.Fatalf("error verifying token: %s", err)
	}
}

type fakeGenericKey struct {
	privateKey *ecdsa.PrivateKey
}

func (fgk *fakeGenericKey) RandReader() io.Reader {
	return rand.Reader
}

func (fgk *fakeGenericKey) Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error) {
	if sig, err := fgk.privateKey.Sign(fgk.RandReader(), digest, opts); err == nil {
		return fmtEcdsaSig(sig)
	}
	return
}

func (fgk *fakeGenericKey) KeyID() string {
	return "fakeKey"
}

func (fgk *fakeGenericKey) Verify(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	var hash crypto.Hash
	switch alg {
	case ES256:
		hash = crypto.SHA256
	case ES384:
		hash = crypto.SHA384
	case ES512:
		hash = crypto.SHA512
	}

	hasher := hash.New()
	if _, err := hasher.Write(payload); err != nil {
		return err
	}

	digest := hasher.Sum(nil)

	r := (&big.Int{}).SetBytes(signature[:len(signature)/2])
	s := (&big.Int{}).SetBytes(signature[len(signature)/2:])
	if !ecdsa.Verify(
		fgk.privateKey.Public().(*ecdsa.PublicKey),
		digest,
		r, s) {
		return errors.New("signature verification failure")
	}
	return nil
}

func fmtEcdsaSig(asn1Sig []byte) (rsSig []byte, err error) {
	type ecSig struct {
		R, S *big.Int
	}
	unmarshalledSig := ecSig{}
	if _, err := asn1.Unmarshal(asn1Sig, &unmarshalledSig); err != nil {
		return nil, err
	}
	rsSig = append(unmarshalledSig.R.Bytes(), unmarshalledSig.S.Bytes()...)
	return
}
