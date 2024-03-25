package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	//check & chage the device(network interface), srcMac(network interface Mac), gtwMac(gateway Mac), hostip
	device      = "en0"
	srcMac      = net.HardwareAddr{0x5c, 0xe9, 0x1e, 0xc2, 0xee, 0x91}
	gtwMac      = net.HardwareAddr{0x24, 0xcf, 0x24, 0xc5, 0x36, 0x32}
	hostip      = "192.168.1.236"
	handleSend  *pcap.Handle
	err         error
	rdata       = ""
	time_format = "2006-01-02 MST 15:04:05.000000"
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}

func Make_Ethernet() *layers.Ethernet {
	return &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMac,
		DstMAC:       gtwMac,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}
}

func Make_IPv4(dstIP string) *layers.IPv4 {
	return &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      net.ParseIP(hostip),
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}
}

func Make_UDP(dstPort layers.UDPPort) *layers.UDP {
	return &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(53),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}
}

func Make_DNS(txid uint16, dns_Questions []layers.DNSQuestion, dns_Answers []layers.DNSResourceRecord, dns_Authorities []layers.DNSResourceRecord, dns_Additionals []layers.DNSResourceRecord) *layers.DNS {
	return &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           txid,
		QR:           true,
		OpCode:       0,
		AA:           true,
		TC:           false,
		RD:           false,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      uint16(len(dns_Questions)),
		ANCount:      uint16(len(dns_Answers)),
		NSCount:      uint16(len(dns_Authorities)),
		ARCount:      uint16(len(dns_Additionals)),
		Questions:    dns_Questions,
		Answers:      dns_Answers,
		Authorities:  dns_Authorities,
		Additionals:  dns_Additionals,
	}
}

func Simp_resp(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32,
	rdata string) {
	loginfo := fmt.Sprintf("[-]%s : fm %s %d query %s Type %s txid %d \n", time.Now().Format(time_format), dstIP, dstPort, qname, qtype.String(), txid)
	fmt.Print(loginfo)
	var log_info string
	ethernetLayer := Make_Ethernet()
	ipv4Layer := Make_IPv4(dstIP)
	udpLayer := Make_UDP(dstPort)
	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		log.Panicln("Error1: ", err)
	}
	var dnsLayer *layers.DNS
	dns_Questions := []layers.DNSQuestion{
		{
			Name:  []byte(qname),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		},
	}
	dnsLayer = Make_DNS(txid, dns_Questions, nil, nil, nil)
	log_info = fmt.Sprintf("[-]%s : to %s with %s %s %d %s\n", time.Now().Format(time_format), dstIP, qname, qtype.String(), ttl, "NO ANSWER")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error2: ", err)
		os.Exit(1)
	}

	outgoingPacket := buffer.Bytes()
	err = handleSend.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	fmt.Printf(log_info)
}

func Defence() {
	fmt.Printf("[+]%s : %s\n", time.Now().Format(time_format), "TsuKing Defence Start")

	handleSend, err = pcap.OpenLive(device, 1024, false, 0*time.Second)
	if err != nil {
		fmt.Println("Error3: ", err)
		os.Exit(1)
	}
	defer handleSend.Close()

	handleRecv, err := pcap.OpenLive(device, 1024, false, time.Nanosecond)
	if err != nil {
		fmt.Println("Error4: ", err)
		os.Exit(1)
	}
	defer handleRecv.Close()

	var filter = fmt.Sprintf("dst host %s and udp dst port %d", hostip, 53)
	err = handleRecv.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("Error5: ", err)
		os.Exit(1)
	}

	err = handleRecv.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("Error6: ", err)
		os.Exit(1)
	}

	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)

	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	packetChan := packetSource.Packets()

	for packet := range packetChan {
		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			continue
		}
		if len(dns_.Questions) <= 0 {
			continue
		}

		dstIP := ipv4.SrcIP.String()
		qname := string(dns_.Questions[0].Name)
		qtype := dns_.Questions[0].Type
		txid := dns_.ID
		dstPort := udp.SrcPort
		ttl := 1200
		rdata_ := rdata

		go Simp_resp(dstIP, dstPort, qname, qtype, txid, uint32(ttl), rdata_)

	}
}

func main() {
	Defence()
}
