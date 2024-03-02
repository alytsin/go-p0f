package p0f

import (
	"github.com/alytsin/go-p0f/signature"
	"github.com/google/gopacket/layers"
	"math/rand"
)

func SpoofIpLayer(ipv4 *layers.IPv4, sig *signature.Signature) {

	// https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler

	// set to zero ECN bits in TOS byte
	tos := ipv4.TOS & ^uint8(0b11)
	flags := ipv4.Flags
	quirks := sig.Quirks

	// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Identification
	identification := ipv4.Id

	// DF: don't fragment bit is set in the IP header
	if quirks.DF {
		flags = flags | layers.IPv4DontFragment

		// id+: df bit is set and IP identification field is non-zero
		if quirks.IdPlus {
			if identification == 0 {
				identification = uint16(rand.Intn(0xFFFF-1) + 1)
			}
		} else {
			identification = 0
		}

		// DF flag is NOT set
	} else {
		flags = flags & ^layers.IPv4DontFragment

		// id-: df bit is not set and IP identification is zero
		if quirks.IdMinus {
			identification = 0
		} else if identification == 0 {
			identification = uint16(rand.Intn(0xFFFF-1) + 1)
		}
	}

	// 0+: reserved ("must be zero") field in IP header is not actually zero
	// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Flags
	if quirks.ZeroPlus {
		flags = flags | layers.IPv4EvilBit
	} else {
		// By default, "evil bit" must be unset
		flags = flags & ^layers.IPv4EvilBit
	}

	// ecn: explicit congestion flag is set, 2 bit field
	// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#ECN
	// https://en.wikipedia.org/wiki/Explicit_Congestion_Notification#Operation_of_ECN_with_IP
	if quirks.ECN {
		tos = tos & uint8(rand.Intn(0b11-1)+1)
	}

	ipv4.TOS = tos
	ipv4.Flags = flags
	ipv4.Id = identification
}
