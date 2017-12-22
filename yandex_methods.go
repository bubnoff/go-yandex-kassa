package yandex

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"encoding/xml"
	"crypto/tls"
	"github.com/fullsailor/pkcs7"
	"os/exec"
	"strconv"
	"time"
)


const URL_PRODUCTION = "https://calypso.yamoney.ru:9094/"
const URL_DEV = "https://bo-demo02.yamoney.ru:9094/"

const CURRENCY_RUB = "643"
const AGENT_ID = 100500


type BalanceRequest struct {
	XMLName       xml.Name `xml:"balanceRequest"`
	AgentId       int      `xml:"agentId,attr"`
	RequestDT     string   `xml:"requestDT,attr"`
	ClientOrderId string   `xml:"clientOrderId,attr"`
}

type TestDepositionRequest struct {
	XMLName       xml.Name `xml:"testDepositionRequest"`
	AgentId       int      `xml:"agentId"`
	RequestDT     string   `xml:"requestDT"`
	ClientOrderId string   `xml:"clientOrderId"`
	DstAccount    string   `xml:"dstAccount"`
	Amount        float64  `xml:"amount"`
	Currency      string   `xml:"currency"`
	Contract      string   `xml:"contract"`
}

type MakeDepositionRequest struct {
	XMLName          xml.Name `xml:"makeDepositionRequest"`
	AgentId          int      `xml:"agentId,attr"`
	RequestDT        string   `xml:"requestDT,attr"`
	ClientOrderId    string   `xml:"clientOrderId,attr"`
	DstAccount       string   `xml:"dstAccount,attr"`
	Amount           string   `xml:"amount,attr"`
	Currency         string   `xml:"currency,attr"`
	Contract         string   `xml:"contract,attr"`
	PofOfferAccepted int      `xml:"paymentParams>pof_offerAccepted"`
}

type MakeDepositionResponse struct {
	XMLName       xml.Name `xml:"makeDepositionResponse"`
	RequestDT     string   `xml:"requestDT,attr"`
	ClientOrderId string   `xml:"clientOrderId,attr"`
	Status        int      `xml:"status,attr"`
	Error         int      `xml:"error,attr"`
}

type BalanceResponse struct {
	XMLName       xml.Name `xml:"makeDepositionResponse"`
	RequestDT     string   `xml:"requestDT,attr"`
	ClientOrderId string   `xml:"clientOrderId,attr"`
	Status        int      `xml:"status,attr"`
	Error         int      `xml:"error,attr"`
}

func (request *BalanceRequest) Prepare() {
	t := time.Now()
	request.ClientOrderId = strconv.FormatInt(int64(time.Now().Unix())*1000, 10)
	request.RequestDT = t.Format(time.RFC3339)
	request.AgentId = AGENT_ID
}

func (request *MakeDepositionRequest) Prepare() {
	t := time.Now()
	request.ClientOrderId = strconv.FormatInt(int64(time.Now().Unix())*1000, 10)
	request.RequestDT = t.Format(time.RFC3339)
	request.AgentId = AGENT_ID
	request.Currency = CURRENCY_RUB
	request.PofOfferAccepted = 1
}

func (request *TestDepositionRequest) Prepare() {
	t := time.Now()
	request.ClientOrderId = strconv.FormatInt(int64(time.Now().Unix())*1000, 10)
	request.RequestDT = t.Format(time.RFC3339)
	request.AgentId = AGENT_ID
}

func GetBalance() (BalanceResponse , error) {

	balance_request := BalanceRequest{}
	balance_request.Prepare()
	bBalanceRequest, _ := xml.Marshal(balance_request)
	response, e := sendMessage(bBalanceRequest, "balance")

	if e != nil {
		return BalanceResponse{}, e
	}

	var qResp BalanceResponse
	xml.Unmarshal(response, &qResp)

	return qResp, nil
}

func PayOnPhone(amount int, number string) (MakeDepositionResponse, error) {

	dep_request := MakeDepositionRequest{}
	dep_request.Prepare()
	dep_request.DstAccount = number
	dep_request.Amount = strconv.Itoa(amount) + ".00"
	dep_request.Contract = "The reason for making the transfer."
	DepRequest, _ := xml.Marshal(dep_request)

	response, e := sendMessage(DepRequest, "makeDeposition")

	if e != nil {
		return MakeDepositionResponse{}, e
	}

	var qResp MakeDepositionResponse
	xml.Unmarshal(response, &qResp)

	return qResp, nil

}

func testDeposition() int {
	//TODO create method
	test_dep_request := TestDepositionRequest{}
	test_dep_request.Prepare()
	return 1

}

func sendMessage(data []byte, method string) (response []byte, err error) {

	df, err := ioutil.ReadFile("cert_from_yandex.cer") // Certificate form yandex

	if err != nil {
		return nil, err
	}
	pk, err := ioutil.ReadFile("private.key")

	if err != nil {
		return nil, err
	}

	tmpfile, err := ioutil.TempFile("", "in_data")
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	if _, err := tmpfile.Write(data); err != nil {
		log.Fatal(err)
		return nil, err
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	pksc7data, _ := exec.Command("sh", "-c",
		"openssl smime -sign -in '"+tmpfile.Name()+"'  -signer 'cert_from_yandex.cer' -inkey 'private.key' -passin pass:'MyPrivatePassKey' -nodetach -nochain -nocerts -outform 'PEM'").Output()

	os.Remove(tmpfile.Name())

	new_cert, err := X509KeyPair(df, pk, []byte("MyPrivatePassKey"))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{new_cert},
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("POST", URL_DEV+"webservice/deposition/api/"+method, bytes.NewBuffer(pksc7data))
	req.Header.Set("Content-Type", "application/pkcs7-mime")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} else {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		pemic, _ := pem.Decode(bodyBytes)
		p, _ := pkcs7.Parse(pemic.Bytes)
		return p.Content, err
	}
}

func X509KeyPair(certPEMBlock, keyPEMBlock, pw []byte) (cert tls.Certificate, err error) {
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		err = errors.New("crypto/tls: failed to parse certificate PEM data")
		return
	}
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			err = errors.New("crypto/tls: failed to parse key PEM data")
			return
		}
		if x509.IsEncryptedPEMBlock(keyDERBlock) {
			out, err2 := x509.DecryptPEMBlock(keyDERBlock, pw)
			if err2 != nil {
				err = err2
				return
			}
			keyDERBlock.Bytes = out
			break
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return
	}
	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("crypto/tls: private key type does not match public key type")
			return
		}
		if pub.N.Cmp(priv.N) != 0 {
			err = errors.New("crypto/tls: private key does not match public key")
			return
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			err = errors.New("crypto/tls: private key type does not match public key type")
			return

		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			err = errors.New("crypto/tls: private key does not match public key")
			return
		}
	default:
		err = errors.New("crypto/tls: unknown public key algorithm")
		return
	}
	return
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	} else {
		fmt.Println("1 -", err)
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	} else {
		fmt.Println("8 -", err)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	} else {
		fmt.Println("ECP -", err)
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}
