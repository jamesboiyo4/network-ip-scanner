package privateIP

import (
	"errors"
	"fmt"
	"inPacket/logs"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/withmandala/go-log"
)

var (
	classAPrivate, classBPrivate, classCPrivate *regexp.Regexp
	device                                      []string
	snapLen                                     int32 = 65535
	promisc                                     bool  = false
	err                                         error
	timeout                                     time.Duration = 1 * time.Second
	handle                                      *pcap.Handle
)

type PrivateIP struct {
	terminalLogger *log.Logger
	wg             sync.WaitGroup
}

func init() {
	classAPrivate = regexp.MustCompile(`^10\.(([1-9]?\d|[12]\d\d)\.){2}([1-9]?\d|[12]\d\d)$`)
	classBPrivate = regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])(\.([1-9]?\d|[12]\d\d)){2}$`)
	classCPrivate = regexp.MustCompile(`^192\.16[6-8](\.([1-9]?\d|[12]\d\d)){2}$`)
}

// CheckInterface uses the net package to scan for interfaces found in the node
func (pIP *PrivateIP) CheckInterface() []string {
	var interfacesSlice []string
	lg := new(logs.WriteLogs)
	pIP.terminalLogger = log.New(os.Stderr)

	interfaces, err := net.Interfaces()
	if err != nil {
		lg.WriteIntoLogFile(err)
		os.Exit(1)
	}

	for _, intaface := range interfaces {
		interfacesSlice = append(interfacesSlice, intaface.Name)
		pIP.terminalLogger.Info("Interfaces found: ", intaface)
	}

	return interfacesSlice
}

func (pIP *PrivateIP) ReadIpandCheck(interfaces []string) {
	pIP.terminalLogger = log.New(os.Stderr)
	lg := new(logs.WriteLogs)
	fmt.Println(interfaces)

	handle, err = pcap.OpenLive("wlp3s0", snapLen, promisc, timeout)
	if err != nil {
		pIP.terminalLogger.Warn(err)
		lg.WriteIntoLogFile(err)
		return
	}
	defer handle.Close()

	var filter string = "ip"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		pIP.terminalLogger.Fatal(err)
		lg.WriteIntoLogFile(err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		pIP.wg.Add(1)
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		ip_packet, _ := ip_layer.(*layers.IPv4)
		fmt.Println("-")

		pIP.terminalLogger.Info("Source Address: ", ip_packet.SrcIP.String())
		pIP.terminalLogger.Info("Destination Address: ", ip_packet.DstIP.String())
		if pIP.checkSourceIp(ip_packet.SrcIP.String()) == true {
			pIP.terminalLogger.Info("Private IP read")

		} else {
			go pIP.Location(ip_packet.SrcIP.String())
			lg.WriteIntoLogFile(errors.New("Public IP found latitude and longitude " + ip_packet.SrcIP.String()))
			pIP.terminalLogger.Error("Public  IP read!")
			pIP.wg.Wait()
		}
	}
}

func (pIP *PrivateIP) checkSourceIp(ip string) bool {
	classAMatch := classAPrivate.MatchString(ip)
	classBMatch := classBPrivate.MatchString(ip)
	classCMatch := classCPrivate.MatchString(ip)
	pIP.terminalLogger = log.New(os.Stderr)

	if classAMatch == true || classBMatch == true || classCMatch == true {
		pIP.terminalLogger.Info("No intruder detected")
		return true
	} else {
		pIP.terminalLogger.Error("Intruder detected")
		return false
	}
}
