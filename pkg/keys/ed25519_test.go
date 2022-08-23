package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type Ed25519Suite struct{}

const keySize = 32 // The ed25519 seed size is 32
var _ = Suite(&Ed25519Suite{})

func (Ed25519Suite) TestUnmarshalEd25519(c *C) {
	pub, _, err := ed25519.GenerateKey(strings.NewReader("00001-deterministic-buffer-for-key-generation"))
	c.Assert(err, IsNil)

	publicKey, err := json.Marshal(map[string]string{
		"public": hex.EncodeToString(pub),
	})
	c.Assert(err, IsNil)

	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      publicKey,
	}
	verifier := NewEd25519Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), IsNil)
}

func FuzzUnmarshal_Ed25519(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) <= keySize { // ed25519 requires strings of len greater than 32
			t.Skip()
		}
		c := &C{}

		pub, _, err := ed25519.GenerateKey(strings.NewReader(s))
		c.Assert(err, IsNil)

		publicKey, err := json.Marshal(map[string]string{
			"public": hex.EncodeToString(pub),
		})
		c.Assert(err, IsNil)

		badKey := &data.PublicKey{
			Type:       data.KeyTypeEd25519,
			Scheme:     data.KeySchemeEd25519,
			Algorithms: data.HashAlgorithms,
			Value:      publicKey,
		}
		verifier := NewEd25519Verifier()
		c.Assert(verifier.UnmarshalPublicKey(badKey), IsNil)
	})

}
func (Ed25519Suite) TestUnmarshalEd25519_Invalid(c *C) {
	badKeyValue, err := json.Marshal(true)
	c.Assert(err, IsNil)
	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      badKeyValue,
	}
	verifier := NewEd25519Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
}

func FuzzUnmarshalEd25519_Invalid(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		c := &C{}
		if len(s) > keySize {
			// We are only testing for lengths greater than the
			// keySize because all other data could be successful.
			t.Skip()
		}
		badKeyValue, err := json.Marshal(s)

		if err != nil {
			t.Skip()
		}
		badKey := &data.PublicKey{
			Type:       data.KeyTypeEd25519,
			Scheme:     data.KeySchemeEd25519,
			Algorithms: data.HashAlgorithms,
			Value:      badKeyValue,
		}
		verifier := NewEd25519Verifier()
		c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
	})

}
func (Ed25519Suite) TestUnmarshalEd25519_FastFuzz(c *C) {
	verifier := NewEd25519Verifier()
	for i := 0; i < 50; i++ {
		// Ensure no basic panic

		f := fuzz.New()
		var publicData data.PublicKey
		f.Fuzz(&publicData)

		verifier.UnmarshalPublicKey(&publicData)
	}
}

func (Ed25519Suite) TestUnmarshalEd25519_TooLongContent(c *C) {
	randomSeed := make([]byte, MaxJSONKeySize)
	_, err := io.ReadFull(rand.Reader, randomSeed)
	c.Assert(err, IsNil)

	tooLongPayload, err := json.Marshal(
		&ed25519Verifier{
			PublicKey: data.HexBytes(hex.EncodeToString(randomSeed)),
		},
	)
	c.Assert(err, IsNil)

	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      tooLongPayload,
	}
	verifier := NewEd25519Verifier()
	err = verifier.UnmarshalPublicKey(badKey)
	c.Assert(errors.Is(err, io.ErrUnexpectedEOF), Equals, true)
}

func (Ed25519Suite) TestSignVerify(c *C) {
	signer, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}
func FuzzSignVerfiy(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		c := &C{}
		signer, err := GenerateEd25519Key()
		c.Assert(err, IsNil)
		msg := []byte(s)
		sig, err := signer.SignMessage(msg)
		c.Assert(err, IsNil)
		publicData := signer.PublicData()
		pubKey, err := GetVerifier(publicData)
		c.Assert(err, IsNil)
		c.Assert(pubKey.Verify(msg, sig), IsNil)
	})
}
