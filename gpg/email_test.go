package gpg

import (
	"bytes"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

const (
	key = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.5
Comment: Hostname: pgp.mit.edu

mQENBFIE6skBCADBdAxIgenoDjPiJJ8RsYIOQqPl3KI1lzdZdcxGw9NU3/5XQgLGPv2dRUuW
utsK2QhDyNacWEwtfhyfna2VR72mmG50WPwezvofebfScnbu+Kr39yn7CaIjzvRGsBnBV5is
I4fLkryK/11lhCAGPidiekSO8+zqe1/e2q/CMSaThZ4XaqHtHTa9TIBh4mJPz/WuOnjQCpci
NHFggSTAGO5mbiz100tuk2CENRpOky5FHPgzuCeYfrCSWFdgkh64/bIM+UoUtebSgWMJ/38A
qVbf5HLzoaqMo1ohVb2ckBKjxx50wYgdO2WeLMnVZgghNSi0mhoPH5y67tKUfJ6W9SdfABEB
AAG0JkplZmYgU2lzc29uIChHUEcgS2V5KSA8amVmZkBiaWdib3kudXM+iQE4BBMBAgAiBQJS
BOrJAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRB9HcNH4znWsFV2CAC55Kzgz4rz
WmZqkzAWO62g/AwJvf5Yqth70QP25PtgHD2KMJ6ywcCY9Ma4+rEpfbL914NqEcDQmPmOKoG3
SdTPRlTc9m7kGGHVblz7ay+TmtPFfNORI9oKPqJMMaqJph6yp6TcqbibVGnJmiO4cOHVh07h
B8lGRhgTI/kWD7eC45VoeBW8x/wWBiwpQC/ziW2cPD+27LPzGueV5kO27iTPSTHHeuSappP/
7Yv/JfBUOALaSpANn/JaGHl13YQceViPvEY4g/bTduwd5D9O3DwjK45FveWH+VBg4tUlmhYS
tv5Ge7eS53ZWF4GH8goqBV8vKvCjrXZXtm5lx9UgDDIyuQENBFIE6skBCADnC1+KuVOHOHm7
i1ZyqDqAXdtQBKmul9huiak1/Hw8y8Zd6ynpngUpL+M/WeNKZtZvsuQqA8SSlAoOMq5zxuSd
6eALCfTkeXWSUDdy8y1/1m4yM55pGMOedpcGwhiRWP3usGUEP0soYCFmubbYbRd0+avAhyWl
V9xaAO762f/Ic9slAHi5Ncmv24n6WZolCAVGkGirgPtINo/3tuVKEu3naK6BnIJ1O3tSU9oQ
Pf8AhN5tRgXyZHYkbfes5L2xJv8prb9Ys5DYJuKkBQl5t+dQil2Q4Qubj7r9cPzSBcABFRVV
2Ec7HvNG9AFstP1/KLzYGScQQ/EwBXp453NJ5HM9ABEBAAGJAR8EGAECAAkFAlIE6skCGwwA
CgkQfR3DR+M51rCMUgf/VDZvpiHw4a87ty+q7LTxVpeCyZVlsoOrx4sjmL8TV5xGNa0rbV9z
CsBump3QPtIxEQOlUaOQ/04fiYLVyLZixTx4GmPWucqrJSyiG+hjcJOzwAkiRajTEIJm/jUI
2PHqINBPGXMOi/mpqN6Yj8Rc0EFzmVKalcDPgQmG59E72QNweHnCvJItGKj8A0r7r0tHcDPD
1KZ1f5m5pP8jFg9lgisEQe7OPZJGerXbWHWNw6tX2M66C7npPwBozBsg0OiwcFUbNuBKfd35
rkoaaoEuOK3ZkIEcuWnwhLon9KjXoH6eYkU6JKapoZu1TzjKKIhBA8rgEfX0SdCa13WgM0fQ
CQ==
=NPBQ
-----END PGP PUBLIC KEY BLOCK-----`
	email = `Date: Mon, 23 Jun 2015 11:40:36 -0400
From: Gopher <%s>
To: Another Gopher <to@example.com>
Subject: Gophers at Gophercon

%s
`
	testKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
2Oj4+ac=
=KECk
-----END PGP PUBLIC KEY BLOCK-----`
)

func init() {
	// simplify testing so we don't have to mock out the mit networking?
	Strategies = []PublicKeyStrategy{
		StrategySearchBody,
	}
}

func TestEmailParsing(t *testing.T) {
	tests := []struct {
		from        string
		body        string
		shouldError bool
	}{
		{
			from:        "jeff@bigboy.us",
			body:        fmt.Sprintf(email, "jeff@bigboy.us", key),
			shouldError: false,
		},
		{
			from:        "jeff@bigboy.us",
			body:        fmt.Sprintf(email, "jeff@bigboy.us", ""),
			shouldError: true,
		},
		{
			from:        "jeff1@bigboy.us",
			body:        fmt.Sprintf(email, "jeff1@bigboy.us", key),
			shouldError: true,
		},
	}
	for _, test := range tests {

		r := strings.NewReader(test.body)
		m, err := mail.ReadMessage(r)
		if err != nil {
			t.Fatal(err)
		}

		res, err := StrategySearchBody(m)
		if err != nil && !test.shouldError {
			t.Error("Should have found a key")
		} else if err != nil {
			continue
		}

		var identityFound bool
		for _, i := range res.Identities {
			if i.UserId.Email == test.from {
				identityFound = true
			}
		}
		if !identityFound && !test.shouldError {
			t.Errorf("Email not found in identity (%v) for email, contents: (%v)", res, test.body)
		} else if test.shouldError && identityFound {
			t.Errorf("Email should NOT be found in identity (%v) for email, contents: (%v)", res, test.body)
		}

	}

}

func TestEmailDecryption(t *testing.T) {
	myCoolMessage := "Testing, testing, 123"

	r, _ := os.Open("fixtures/test.key")
	ring, _ := openpgp.ReadArmoredKeyRing(r)
	privKey := ring[0]

	pubKey, _ := openpgp.ReadArmoredKeyRing(strings.NewReader(testKey))

	var encryptedBuf bytes.Buffer
	err := Encrypt(privKey, pubKey[0], &encryptedBuf, myCoolMessage)
	if err != nil {
		t.Fatal("Encryption should not fail...", err)
	}

	emailBody := string(encryptedBuf.Bytes()) + "\n\nMy Public Key:\n" + testKey

	// fmt.Printf(email, "test@bigboy.us", emailBody)
	er := strings.NewReader(fmt.Sprintf(email, "test@bigboy.us", emailBody))
	m, _ := mail.ReadMessage(er)
	output, err := DecryptEmail(m, privKey)
	if err != nil {
		t.Errorf("we SHOULD be able to decrypt this email (%s)", err)
	}
	if output.String() != myCoolMessage {
		t.Error("The messages aren't the same :(")
	}
}
