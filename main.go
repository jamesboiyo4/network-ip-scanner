package main

import (
	"errors"
	"inPacket/logs"
	"inPacket/privateIP"
	"time"
)

func main() {
	lgs := new(logs.WriteLogs)
	pIP := new(privateIP.PrivateIP)

	lgs.WriteIntoLogFile(errors.New("Logs for " + time.Now().String()))
	interfaces := pIP.CheckInterface()
	pIP.ReadIpandCheck(interfaces)

	/*flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("filename not specified")
	}
	filename = flag.Args()[0]
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", serveWs)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}*/
}
