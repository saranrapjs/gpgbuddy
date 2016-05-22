package gpg

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yhat/scrape"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// MITHost defines which protocol + hostname we fetch the mit data from.
var MITHost string

func init() {
	MITHost = "https://pgp.mit.edu"
}

const (
	// https://pgp.mit.edu/pks/lookup?search=jeff%40bigboy.us&op=index&exact=on
	mitSearchURL = "%s/pks/lookup?search=%s&op=index&exact=on"
	// https://pgp.mit.edu/pks/lookup?op=get&search=0x7D1DC347E339D6B0
	mitKeyURL = "%s/pks/lookup?op=get"
)

// SearchEmailMIT looks for a GPG key in the pgp.mit.edu database.
func SearchEmailMIT(email string, client *http.Client) (*openpgp.Entity, error) {
	results, err := doSearch(email, client)
	if err != nil || len(results) < 1 {
		return nil, err
	}
	bestGuessKeyURL := results[0]
	key, err := fetchKey(bestGuessKeyURL, client)
	if err != nil {
		return nil, err
	}
	for _, i := range key.Identities {
		if i.UserId.Email == email {
			return key, nil
		}
	}
	return nil, errors.New("Identity mismatch")
}

func doSearch(email string, client *http.Client) ([]string, error) {
	var results []string
	req, _ := http.NewRequest("GET", fmt.Sprintf(mitSearchURL, MITHost, url.QueryEscape(email)), nil)

	res, err := client.Do(req)
	if err != nil {
		return results, err
	}

	root, err := html.Parse(res.Body)
	if err != nil {
		return results, err
	}

	matcher := func(n *html.Node) bool {
		return n.DataAtom == atom.A && n.Parent != nil && n.Parent.Parent != nil
	}

	links := scrape.FindAll(root, matcher)
	for _, link := range links {
		href := scrape.Attr(link, "href")
		href = MITHost + href
		results = append(results, href)
		break
	}

	return results, nil
}

func fetchKey(url string, client *http.Client) (*openpgp.Entity, error) {
	if !strings.Contains(url, fmt.Sprintf(mitKeyURL, MITHost)) {
		return nil, fmt.Errorf("Invalid key URL: %s", url)
	}

	req, _ := http.NewRequest("GET", url, nil)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	root, err := html.Parse(res.Body)
	if err != nil {
		return nil, err
	}

	matcher := func(n *html.Node) bool {
		return n.DataAtom == atom.Pre && n.Parent != nil && n.Parent.Parent != nil
	}
	var keyText string
	pres := scrape.FindAll(root, matcher)
	for _, pre := range pres {
		keyText = scrape.Text(pre)
		break
	}

	if keyText == "" {
		return nil, errors.New("couldnt find key text")
	}

	r := strings.NewReader(keyText)

	keys, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil || len(keys) < 1 {
		return nil, err
	}

	return keys[0], nil
}
