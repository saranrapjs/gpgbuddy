package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/net/context"

	"github.com/saranrapjs/gpgbuddy/gpg"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	gm "google.golang.org/appengine/mail"
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/_ah/mail/", incomingMail)
}

// PrivateKey is our unpassword-ed private key.
type PrivateKey struct {
	Value string `datastore:",noindex"`
}

const preamble = `I was able to read your encrypted email; what follows is an encrypted message just for you:
`

func getKey(ctx context.Context) (*openpgp.Entity, error) {
	k := datastore.NewKey(ctx, "PrivateKey", "private_key", 0, nil)
	p := new(PrivateKey)
	if err := datastore.Get(ctx, k, p); err != nil {
		return nil, err
	}

	r := strings.NewReader(p.Value)
	ring, _ := openpgp.ReadArmoredKeyRing(r)
	if len(ring) < 1 {
		return nil, errors.New("we are missing a key")
	}
	return ring[0], nil
}

func incomingMail(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	defer r.Body.Close()

	client := urlfetch.Client(ctx)
	gpg.HTTPClient = client

	m, err := mail.ReadMessage(r.Body)
	if err != nil {
		log.Errorf(ctx, "Error reading body: %v", err)
		return
	}
	privKey, err := getKey(ctx)
	if err != nil {
		log.Errorf(ctx, "Error getting key: %v", err)
		return
	}

	output, err := gpg.DecryptEmail(m, privKey)
	if err != nil {
		log.Errorf(ctx, "Error decrypting: %v", err)
		return
	}
	log.Infof(ctx, "Received mail: %v", m.Header.Get("From"))

	newMsg := "Congratulations on successfully setting up PGP/GPG 🕶\n"
	newMsg = newMsg + "> " + output.String()

	addrs, err := m.Header.AddressList("From")
	if err != nil || len(addrs) < 1 {
		log.Errorf(ctx, "Error addressing emails")
		return
	}
	sendTo := addrs[0].Address
	var enc bytes.Buffer

	if err := gpg.Encrypt(privKey, output.TheirKey, &enc, newMsg); err != nil {
		log.Errorf(ctx, "Error encrypting to %v", sendTo)
	}

	om := &gm.Message{
		Sender:  "GPG Buddy <test@gpgbuddy.appspotmail.com>",
		To:      []string{sendTo},
		Subject: "SUCCESS! Now, an encrypted email for you...",
		Body:    preamble + string(enc.Bytes()),
	}
	if err := gm.Send(ctx, om); err != nil {
		log.Errorf(ctx, "Couldn't send email: %v", err)
	}
}
