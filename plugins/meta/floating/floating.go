// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

const (
	defaultNoVlanEth = "eth1"
	defaultVlanEth   = "eth1"

	defaultNoVlanBrName                 = "floating"
	defaultContainerFloatingipInterface = "eth1"
)

// Route is route for ipallocation and ipam
type Route struct {
	Dst types.IPNet `json:"dst"`
}

type FloaingIPEntry struct {
	IP      net.IP      `json:"Ip"`
	SubNet  types.IPNet `json:"Subnet"`
	Gateway net.IP      `json:"Gateway"`
	Vlan    string      `json:"Vlan,omitempty"`
	// Flag stand whether use Floatingip feature
	Flag bool `json:"Flag"`

	Routes string `json:"routes"`
}

type NetConf struct {
	types.NetConf
	NoVlanBrName  string                 `json:"novlanbrname"`
	NoVlanEth     string                 `json:"novlaneth"`
	VlanEth       string                 `json:"vlaneth"`
	Delegate      map[string]interface{} `json:"delegate"`
	RuntimeConfig struct {
		FloatingIP FloaingIPEntry `json:"floatingip,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

type subnetEnv struct {
	nw     *net.IPNet
	sn     *net.IPNet
	mtu    *uint
	ipmasq *bool
}

func loadFloatingNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{
		NoVlanBrName: defaultNoVlanBrName,
		NoVlanEth:    defaultNoVlanEth,
		VlanEth:      defaultVlanEth,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

func isString(i interface{}) bool {
	_, ok := i.(string)
	return ok
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadFloatingNetConf(args.StdinData)
	if err != nil {
		return err
	}

	Logger.Printf("get data %++v\n", n.RuntimeConfig.FloatingIP)

	return cmdAddOperatorFloatingIP(n, args)
}

func cmdDel(args *skel.CmdArgs) error {
	return nil
	/*
		nc, err := loadFloatingNetConf(args.StdinData)
		if err != nil {
			return err
		}

		netconfBytes, err := consumeScratchNetConf(args.ContainerID, nc.DataDir)
		if err != nil {
			if os.IsNotExist(err) {
				// Per spec should ignore error if resources are missing / already removed
				return nil
			}
			return err
		}

		n := &types.NetConf{}
		if err = json.Unmarshal(netconfBytes, n); err != nil {
			return fmt.Errorf("failed to parse netconf: %v", err)
		}

		return invoke.DelegateDel(n.Type, netconfBytes)
	*/
}

var Logger *log.Logger

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	logPath := "/var/log/cni"
	if err := os.MkdirAll(logPath, os.ModePerm); err != nil {
		log.Fatalf("create logpath %v error %v", logPath, err)
	}
	logfile, err := os.OpenFile(filepath.Join(logPath, "flannel.log"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("open log file error")
	}
	Logger = log.New(logfile, "", log.Ldate|log.Llongfile|log.Ltime)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
