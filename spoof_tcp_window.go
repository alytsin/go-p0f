package p0f

import (
	"encoding/binary"
	"github.com/alytsin/go-p0f/signature"
	"github.com/google/gopacket/layers"
)

func SpoofTcpWindow(tcp *layers.TCP, sig *signature.Signature) {

	switch sig.WindowSize.WindowSizeType {
	case signature.WindowTypeNormal:
		tcp.Window = sig.WindowSize.WindowSize
		return
	case signature.WindowTypeMSS:
		for _, option := range tcp.Options {
			if option.OptionType == layers.TCPOptionKindMSS {
				if len(option.OptionData) >= 2 {
					tcp.Window = binary.BigEndian.Uint16(option.OptionData) * sig.WindowSize.WindowSize
					return
				}
			}
		}
		panic("TCP window value requires MSS, but MSS option is not set on packet")
	case signature.WindowTypeMTU:
		// TODO
	case signature.WindowTypeMod:
		// TODO
	}

	// WindowTypeAny
}
