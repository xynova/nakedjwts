package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/ovh/configstore"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/xynova/nakedjwts/pkg/web"
	"testing"
)

func TestChallengeRequested(t *testing.T) {

	return
	//var (
	//	output string
	//	// Exactly what CURL does
	//	expected = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAMAA="
	//	roundTripper http.RoundTripper = &http.Transport{}
	//)
	//
	//handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//	output = r.Header.Get("Authorization")
	//})
	//
	//s:=httptest.NewServer(handler)
	//defer s.Close()
	//
	//auth := &ntlm2Authenticator{ }
	//
	//auth.execChallengeRequest(s.URL, &roundTripper)
	//
	//if output != expected {
	//	t.Errorf("Invalid negotiate message %s: expected %s", output, expected)
	//}


	item := configstore.NewItem("encryption-key", `{"identifier":"storage","cipher":"aes-gcm","timestamp":1559309532,"key":"eb6a942c0c0c75cc87f37d9e880c440ac124e040f263611d9d236b8ed92e35521"}`, 0)
	store := configstore.NewStore()
	store.InMemory("memory").Add(item)
	k,err := keyloader.LoadKeyFromStore("storage",store)
	if err != nil {
		panic(err)
	}

	fmt.Println(k)
	//
	encrypted, err := k.Encrypt([]byte("foobar"), []byte("additional"), []byte("mac"), []byte("data"))
	if err != nil {
		panic(err)
	}

	// decryption will fail if you do not provide the same additional data
	// of course, you can also encrypt/decrypt without additional data
	decrypted, err := k.Decrypt(encrypted, []byte("additional"), []byte("mac"), []byte("data"))
	if err != nil {
		panic(err)
	}

	// output: foobar
	fmt.Println(string(decrypted))
}


func TestSomethingElse(t *testing.T) {
	privateKey, _ := web.ReadRsaPrivateKey("../../ignore.key.priv")

	h := sha256.New()
	h.Write(privateKey.D.Bytes())
	sum := h.Sum(nil)
	fmt.Printf("%x \n", h.Sum(nil))
	fmt.Printf("%v \n", len(sum))

}
