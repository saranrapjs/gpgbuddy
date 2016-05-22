package server

import (
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
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/_ah/mail/", incomingMail)
}

// PrivateKey is our unpassword-ed private key.
type PrivateKey struct {
	Value string `datastore:",noindex"`
}

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
	log.Infof(ctx, "Received mail: %v %v", output, err)

}
