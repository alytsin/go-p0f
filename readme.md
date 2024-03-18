<h1>Minimal p0f implementation written in Golang</h1>

<b>Usage example</b>

```golang
package main

import(
    "github.com/alytsin/go-p0f"
    "github.com/alytsin/go-p0f/signature"
)

func main() {
	// parse signature
	parser := signature.Parser{}
	parsedSignature, _ := parser.Parse("*:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol,eol:df,id+:0")

	var ipLayer *layers.IPv4
	var tcpLayer *layers.TCP

	// do parse packet layers here

	// spoof packet
	p0f.SpoofIpLayer(ipLayer, parsedSignature)
	p0f.SpoofTcpLayer(tcpLayer, parsedSignature)

	// serialize layers back to packet
	// gopacket.SerializeLayers

}
```

