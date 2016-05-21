package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Encrypt encrypts a text msg into a plaintext gpg-signed string.
func Encrypt(myPrivateKey *openpgp.Entity, theirPublicKey *openpgp.Entity, writer io.Writer, msg string) error {
	if err := myPrivateKey.PrivateKey.Decrypt([]byte("")); err != nil {
		return err
	}

	w, _ := armor.Encode(writer, "PGP MESSAGE", nil)
	plaintext, err := openpgp.Encrypt(w, []*openpgp.Entity{theirPublicKey}, myPrivateKey, nil, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(plaintext, msg)
	plaintext.Close()
	w.Close()
	return nil
}

func prompt(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	return []byte(""), nil
}

// Decrypt decrypts a reader into a plaintext decrypted string.
func Decrypt(myPrivateKey *openpgp.Entity, theirPublicKey *openpgp.Entity, reader io.Reader) (io.Reader, error) {
	if myPrivateKey.PrivateKey == nil || theirPublicKey.PrimaryKey == nil {
		return nil, errors.New("sanity-check: we need a private + public key")
	}
	var entityList openpgp.EntityList
	if err := myPrivateKey.PrivateKey.Decrypt([]byte("")); err != nil {
		return nil, err
	}
	var w bytes.Buffer
	if err := myPrivateKey.SerializePrivate(&w, nil); err != nil {
		return nil, err
	}
	if err := theirPublicKey.Serialize(&w); err != nil {
		return nil, err
	}

	entityList, err := openpgp.ReadKeyRing(&w)
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(reader, entityList, prompt, nil)
	if err != nil {
		return nil, err
	}
	return md.UnverifiedBody, nil
}
