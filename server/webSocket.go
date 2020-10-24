package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/net/websocket"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"ssh2web/ssh"
	"strings"
	"time"
)


func StartWebSocket(addr string,keyFile string,certFile string) error {
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.Handle("/ssh", websocket.Handler(webToSsh))
	if(keyFile==""||certFile==""){
		keyFile="localhost_server.key"
		certFile="localhost_server.pem"
		addrs:=strings.Split(addr,":")
		var ip="127.0.0.1";
		if(addrs[0]!="0.0.0.0"||addrs[0]!=""){
			ip=addrs[0];
		}
		_,err:=os.Stat(keyFile)
		if(err!=nil){
			genCERT("improvement","localhost",ip);
		}
	}
	err :=http.ListenAndServeTLS(addr,certFile,keyFile,nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
	return nil;
}


/* to ssh server*/
func webToSsh(ws *websocket.Conn) {
	token:=ws.Request().FormValue("token")
	decodeBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		ws.Write([]byte("err:"+err.Error()))
		return
	}
	if(len(decodeBytes)==0){
		ws.Write([]byte("token null"+token))
		return
	}

	userInfo:= make(map[string]string)
	err = json.Unmarshal(decodeBytes, &userInfo)
	if err != nil {
		ws.Write([]byte("err:"+err.Error()))
		return
	}

	var user string;
	if _user, ok := userInfo["user"]; ok {
		user=_user;
	}
	if(len(user)==0){
		ws.Write([]byte("user is null :"+user))
		return
	}
	var host string;
	if _host, ok := userInfo["host"]; ok {
		host=_host;
	}
	if(len(host)==0){
		ws.Write([]byte("host is null :"+host))
		return
	}

	var password string=""
	if _password, ok := userInfo["password"]; ok {
		password=_password;
	}
	var key string="";
	if _key, ok := userInfo["key"]; ok{
		key=_key;
	}
	ssh.ToSSH(host,user,password,key,ws);
}


/*
 *生成证书,
 */
func genCERT(organization string,host string,ip string) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	privCa, _ := rsa.GenerateKey(rand.Reader, 1024)
	CreateCertificateFile(host+"_ca", ca, privCa, ca, nil)
	server := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	hosts := []string{host, ip}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			server.IPAddresses = append(server.IPAddresses, ip)
		} else {
			server.DNSNames = append(server.DNSNames, h)
		}
	}
	privSer, _ := rsa.GenerateKey(rand.Reader, 1024)
	CreateCertificateFile(host+"_server", server, privSer, ca, privCa)
}

func CreateCertificateFile(name string, cert *x509.Certificate, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	priv := key
	pub := &priv.PublicKey
	privPm := priv
	if caKey != nil {
		privPm = caKey
	}
	ca_b, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, privPm)
	if err != nil {
		log.Println("create failed", err)
		return
	}
	ca_f := name + ".pem"
	var certificate = &pem.Block{Type: "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   ca_b}
	ca_b64 := pem.EncodeToMemory(certificate)
	ioutil.WriteFile(ca_f, ca_b64, 0777)

	priv_f := name + ".key"
	priv_b := x509.MarshalPKCS1PrivateKey(priv)
	ioutil.WriteFile(priv_f, priv_b, 0777)
	var privateKey = &pem.Block{Type: "PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   priv_b}
	priv_b64 := pem.EncodeToMemory(privateKey)
	ioutil.WriteFile(priv_f, priv_b64, 0777)
}