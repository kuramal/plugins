/*
#  #############################################
#  Copyright (c) 2019-2039 All rights reserved.
#  #############################################
#
#  Name:  floatingip.go
#  Date:  2019-03-18 10:00
#  Author:   zhangjie
#  Email:   iamzhangjie0619@163.com
#  Desc:
#
*/

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
)

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func cmdAddOperatorFloatingIP(n *NetConf, args *skel.CmdArgs) error {
	if !n.RuntimeConfig.FloatingIP.Flag {
		return nil
	}
	vlan, err := strconv.Atoi(n.RuntimeConfig.FloatingIP.Vlan)
	if err != nil {
		return err
	}
	if vlan == -1 {
		return operatorNoVlan(n, args.Netns)
	}
	return operatorVlan(n, vlan, args.Netns)
}

func operatorVlan(n *NetConf, vlan int, nns string) error {

	vlaninterface, err := createVlan(n.VlanEth, vlan)
	if err != nil {
		return err
	}

	brname := fmt.Sprintf("%v%v", defaultNoVlanBrName, vlan)
	br, brInterface, err := setupBridge(brname)
	if err != nil {
		return err
	}

	// need to lookup vlaneth to ensure whether addif it`s br
	vlaneth, err := netlink.LinkByName(vlaninterface.Name)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", n.NoVlanEth, err)
	}

	// novlaneth must need master
	// brctl addif br eth1
	if vlaneth.Attrs().MasterIndex == 0 {
		if err := netlink.LinkSetMaster(vlaneth, br); err != nil {
			Logger.Printf("vlan %v set master %v error %V", vlaneth.Attrs().Name, br.Name, err)
			return err
		}
		Logger.Printf("vlan %v set master %v successful", vlaneth.Attrs().Name, br.Name)
	}

	netns, err := ns.GetNS(nns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := setupVeth(netns, br, defaultContainerFloatingipInterface, 0, false)
	if err != nil {
		return err
	}

	ips := make([]*current.IPConfig, 0, 1)
	ipc := &current.IPConfig{
		Address:   net.IPNet{IP: n.RuntimeConfig.FloatingIP.IP, Mask: n.RuntimeConfig.FloatingIP.SubNet.Mask},
		Gateway:   n.RuntimeConfig.FloatingIP.Gateway,
		Interface: current.Int(2),
	}

	troutes, err := routeStr2Routes(n.RuntimeConfig.FloatingIP.Routes)
	if err != nil {
		return err
	}

	result := &current.Result{
		Interfaces: []*current.Interface{brInterface, hostInterface, containerInterface},
		IPs:        append(ips, ipc),
		Routes:     troutes,
	}
	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		contVeth, err := net.InterfaceByName(defaultContainerFloatingipInterface)
		if err != nil {
			return err
		}

		// Add the IP to the interface
		if err := configureIface(defaultContainerFloatingipInterface, result); err != nil {
			return err
		}

		// Send a gratuitous arp
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return types.PrintResult(result, "0.3.0")
}

func operatorNoVlan(n *NetConf, nns string) error {

	br, brInterface, err := setupBridge(n.NoVlanBrName)
	if err != nil {
		return err
	}

	// need to lookup novlaneth to ensure whether addif it`s br
	novlaneth, err := netlink.LinkByName(n.NoVlanEth)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", n.NoVlanEth, err)
	}

	// novlaneth must need master
	// brctl addif br eth1
	if novlaneth.Attrs().MasterIndex == 0 {
		if err := netlink.LinkSetMaster(novlaneth, br); err != nil {
			return err
		}
	}

	netns, err := ns.GetNS(nns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", nns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := setupVeth(netns, br, defaultContainerFloatingipInterface, 0, false)
	if err != nil {
		return err
	}
	ips := make([]*current.IPConfig, 0, 1)
	ipc := &current.IPConfig{
		Address:   net.IPNet{IP: n.RuntimeConfig.FloatingIP.IP, Mask: n.RuntimeConfig.FloatingIP.SubNet.Mask},
		Gateway:   n.RuntimeConfig.FloatingIP.Gateway,
		Interface: current.Int(2),
	}

	troutes, err := routeStr2Routes(n.RuntimeConfig.FloatingIP.Routes)
	if err != nil {
		return err
	}

	result := &current.Result{
		Interfaces: []*current.Interface{brInterface, hostInterface, containerInterface},
		IPs:        append(ips, ipc),
		Routes:     troutes,
	}
	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		contVeth, err := net.InterfaceByName(defaultContainerFloatingipInterface)
		if err != nil {
			return err
		}

		// Add the IP to the interface
		if err := configureIface(defaultContainerFloatingipInterface, result); err != nil {
			return err
		}

		// Send a gratuitous arp
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return types.PrintResult(result, "0.3.0")
}

func createVlan(master string, vlanid int) (*current.Interface, error) {

	m, err := netlink.LinkByName(master)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", master, err)
	}

	ifName := fmt.Sprintf("%v_%v", master, vlanid)

	v := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         m.Attrs().MTU,
			Name:        ifName,
			ParentIndex: m.Attrs().Index,
		},
		VlanId: vlanid,
	}

	if err := netlink.LinkAdd(v); err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("failed to create vlan id %v: %v", vlanid, err)
	}

	// Re-fetch interface to get all properties/attributes
	contVlan, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to refetch vlan %q: %v", ifName, err)
	}

	vlan := &current.Interface{
		Name: ifName,
		Mac:  contVlan.Attrs().HardwareAddr.String(),
	}

	err = netlink.LinkSetUp(contVlan)
	if err != nil {
		return nil, err
	}

	return vlan, nil
}

func routeStr2Routes(rs string) ([]*types.Route, error) {
	r := make([]*types.Route, 0, 3)
	err := json.Unmarshal([]byte(rs), &r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ConfigureIface takes the result of IPAM plugin and
// applies to the ifName interface
func configureIface(ifName string, res *current.Result) error {
	if len(res.Interfaces) == 0 {
		return fmt.Errorf("no interfaces to configure")
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if len(res.IPs) != 1 {
		return fmt.Errorf("len of result.Ips must 1")
	}
	ipc := res.IPs[0]
	if ipc.Interface == nil {
		return nil
	}
	intIdx := *ipc.Interface
	if intIdx < 0 || intIdx >= len(res.Interfaces) || res.Interfaces[intIdx].Name != ifName {
		// IP address is for a different interface
		return fmt.Errorf("failed to add IP addr %v to %q: invalid interface index", ipc, ifName)
	}

	addr := &netlink.Addr{IPNet: &ipc.Address, Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP addr %v to %q: %v", ipc, ifName, err)
	}

	// set route
	for _, r := range res.Routes {
		if err = ip.AddRoute(&r.Dst, r.GW, link); err != nil {
			// we skip over duplicate routes as we assume the first one wins
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%v via %v dev %v': %v", r.Dst, r.GW, ifName, err)
			}
		}
	}
	return nil
}

func setupVeth(netns ns.NetNS, br *netlink.Bridge, ifName string, mtu int, hairpinMode bool) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	// connect host veth end to the bridge
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		return nil, nil, fmt.Errorf("failed to connect %q to bridge %v: %v", hostVeth.Attrs().Name, br.Attrs().Name, err)
	}

	// set hairpin mode
	if err = netlink.LinkSetHairpin(hostVeth, hairpinMode); err != nil {
		return nil, nil, fmt.Errorf("failed to setup hairpin mode for %v: %v", hostVeth.Attrs().Name, err)
	}

	return hostIface, contIface, nil
}

func setupBridge(brname string) (*netlink.Bridge, *current.Interface, error) {
	// create bridge if necessary
	br, err := ensureBridge(brname, 0, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bridge %q: %v", brname, err)
	}

	return br, &current.Interface{
		Name: br.Attrs().Name,
		Mac:  br.Attrs().HardwareAddr.String(),
	}, nil
}

func ensureBridge(brName string, mtu int, promiscMode bool) (*netlink.Bridge, error) {

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}

	err := netlink.LinkAdd(br)
	if err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("could not add %q: %v", brName, err)
	}

	if promiscMode {
		if err := netlink.SetPromiscOn(br); err != nil {
			return nil, fmt.Errorf("could not set promiscuous mode on %q: %v", brName, err)
		}
	}

	// Re-fetch link to read all attributes and if it already existed,
	// ensure it's really a bridge with similar configuration
	br, err = bridgeByName(brName)
	if err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}

	return br, nil
}

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}
