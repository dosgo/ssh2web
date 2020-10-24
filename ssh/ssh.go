package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func ToSSH(host string,user string,password string,key string,ws *websocket.Conn){
	config := ssh.ClientConfig{User:user,HostKeyCallback:ssh.InsecureIgnoreHostKey()}
	if(len(password)>0){
		config.Auth=[]ssh.AuthMethod{ssh.Password(password)};
	}
	if(len(key)>0){
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if(err!=nil){
			ws.Write([]byte("err:"+err.Error()))
			return
		}
		config.Auth=[]ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		}
	}
	if(len(key)==0 &&len(password)==0){
		ws.Write([]byte("password or key not null"));
		return
	}



	// 建立SSH客户端连接
	client, err := ssh.Dial("tcp", host,&config)
	if err != nil {
		ws.Write([]byte("err:"+err.Error()))
		return
	}

	// 建立新会话
	session, err := client.NewSession()
	defer session.Close()
	if err != nil {
		ws.Write([]byte("err:"+err.Error()))
		return
	}


	session.Stdout=ws;
	session.Stdin=ws;
	session.Stderr=ws;


	modes := ssh.TerminalModes{
		ssh.ECHO:          0,  // 禁用回显（0禁用，1启动）
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, //output speed = 14.4kbaud
	}
	if err = session.RequestPty("linux", 32, 160, modes); err != nil {
		log.Printf("request pty error: %s", err.Error())
	}
	if err = session.Shell(); err != nil {
		log.Printf("start shell error: %s", err.Error())
	}
	if err = session.Wait(); err != nil {
		log.Printf("return error: %s", err.Error())
	}
	return ;
}

func getHostKey(host string) (ssh.PublicKey, error) {
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, errors.New(fmt.Sprintf("error parsing %q: %v", fields[2], err))
			}
			break
		}
	}
	if hostKey == nil {
		return nil, errors.New(fmt.Sprintf("no hostkey for %s", host))
	}
	return hostKey, nil
}