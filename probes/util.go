package probes

import (
	"log"
	"net"
	"strconv"
	"strings"
)

var localIP = ""
var localIFIndex = 0
var localIFName = ""

func GetLocalIP() (string, int, string) {
	if localIP != "" {
		return localIP, localIFIndex, localIFName
	}
	addrs, iface, iname, err := getLocalNetAddrs()
	if err != nil {
		log.Printf("get local ip addr error: %s", err)
	}
	localIFIndex = iface
	localIFName = iname
	localIP = addrs
	return localIP, iface, iname
}

func getLocalNetAddrs() (ipStr string, iIndex int, iName string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // 忽略禁用的网卡
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // 忽略loopback回路接口
		}

		// 忽略 docker网桥与虚拟网络
		if strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "veth") ||
			strings.HasPrefix(iface.Name, "br-") ||
			strings.HasPrefix(iface.Name, "w-") ||
			strings.HasPrefix(iface.Name, "vEthernet") {
			continue
		}

		addrs, ierr := iface.Addrs()
		if ierr != nil {
			err = ierr
			return
		}

		for _, addr := range addrs {

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // 不是ipv4地址，放弃
			}

			ipStr = ip.String()
			if isIntranet(ipStr) {
				iIndex = iface.Index
				iName = iface.Name
				return
			}
		}
	}
	return
}

func isIntranet(ipStr string) bool {

	if strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}

	if strings.HasPrefix(ipStr, "172.") {
		// 172.16.0.0-172.31.255.255
		arr := strings.Split(ipStr, ".")
		if len(arr) != 4 {
			return false
		}

		second, err := strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			return false
		}

		if second >= 16 && second <= 31 {
			return true
		}
	}
	return false
}
