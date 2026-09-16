// Command bomly-plugin-syft-detector serves the Syft detector as a managed Bomly
// plugin over the HashiCorp go-plugin gRPC transport. The binary is launched
// and supervised by Bomly; it is not meant to be run by hand.
package main

import (
	"github.com/bomly-dev/bomly-plugin-syft-detector/plugin"

	"github.com/bomly-dev/bomly-sdk/runtime"
)

func main() { runtime.ServeModule(plugin.Module()) }
