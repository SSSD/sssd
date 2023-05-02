package main

import (
	"C"
	"golang.org/x/crypto/ssh"
	"log"
)


func check_error(e error){
	if e != nil {
		log.Fatalf("Failed due to: %s", e)
	}
}


//export ssh_remote
func ssh_remote(user *C.char, machine *C.char, password *C.char, command *C.char)*C.char {
	config := &ssh.ClientConfig{
		User:C.GoString(user),
		Auth: []ssh.AuthMethod{
			ssh.Password(C.GoString(password)),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", C.GoString(machine), config)
	check_error(err)
	defer client.Close()
	session, err := client.NewSession()
	check_error(err)
	defer session.Close()
	output, err := session.Output(C.GoString(command))
	check_error(err)
	return C.CString(string(output))
}


func main() {}
