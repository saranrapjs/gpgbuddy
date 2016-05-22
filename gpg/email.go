package gpg

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/mail"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// HTTPClient is exposed for appengine?
var HTTPClient *http.Client

// Strategies lists the package-supported public key derival strategies.
var Strategies []PublicKeyStrategy

func init() {
	HTTPClient = http.DefaultClient
	Strategies = []PublicKeyStrategy{
		StrategySearchBody,
		StrategySearchMIT,
	}
}

// PublicKeyStrategy is a custom type for finding a public key in an email.
type PublicKeyStrategy func(msg *mail.Message) (*openpgp.Entity, error)

// StrategySearchMIT searches an email's "From" address for a potential MIT match.
func StrategySearchMIT(msg *mail.Message) (*openpgp.Entity, error) {
	return SearchEmailMIT(msg.Header.Get("From"), HTTPClient)
}

// FindBlock finds an ASCII-armored block in a reader string.
func FindBlock(r io.Reader) (*armor.Block, error) {
	block, err := armor.Decode(r)
	if err == io.EOF {
		return nil, errors.New("no armored data found")
	}
	if err != nil {
		return nil, err
	}
	return block, nil
}

// MessageType is the armored block type for a PGP-signed message.
// NB: are there other types? :(
var MessageType = "PGP MESSAGE"

// FindBlockOfType an ASCII-armored block, of a given type,
// from an armored reader.
func FindBlockOfType(r io.Reader, t string) (*armor.Block, error) {
	block, err := FindBlock(r)
	if err != nil {
		return nil, err
	}
	if block.Type != t {
		return FindBlockOfType(r, t)
	}
	return block, nil
}

// StrategySearchBody searches an email's body for a public key.
func StrategySearchBody(msg *mail.Message) (*openpgp.Entity, error) {
	block, err := FindBlockOfType(msg.Body, openpgp.PublicKeyType)
	if err != nil {
		return nil, err
	}
	keys, err := openpgp.ReadKeyRing(block.Body)
	if err != nil || len(keys) < 1 {
		return nil, errors.New("could not find a public key")
	}

	return keys[0], nil
}

// DeriveKeyFromEmail attempts various strategies to pull down a public key, given an
// email. Currently supported: StrategySearchBody, StrategySearchMIT.
func DeriveKeyFromEmail(msg *mail.Message) (*openpgp.Entity, error) {
	buf, _ := ioutil.ReadAll(msg.Body)
	for _, strat := range Strategies {
		bb := bytes.NewBuffer(buf)
		msg.Body = bb
		res, err := strat(msg)
		if err == nil && res != nil {
			msg.Body = bytes.NewBuffer(buf)
			return res, nil
		}
	}
	return nil, errors.New("no public key found")
}

// DecryptEmail takes an email + private key, and returns the unencrypted body as a string.
func DecryptEmail(msg *mail.Message, myPrivateKey *openpgp.Entity) (string, error) {
	theirPublicKey, err := DeriveKeyFromEmail(msg)
	if err != nil {
		return "", err
	}

	block, err := FindBlockOfType(msg.Body, MessageType)
	if err != nil {
		return "", err
	}

	if myPrivateKey == nil {
		return "", errors.New("private key is nil")
	}

	if theirPublicKey == nil {
		return "", errors.New("public key is nil")
	}

	m, err := Decrypt(myPrivateKey, theirPublicKey, block.Body)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(m)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
