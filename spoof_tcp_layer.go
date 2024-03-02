package p0f

import (
	"github.com/alytsin/go-p0f/signature"
	"github.com/google/gopacket/layers"
	"math/rand"
)

func SpoofTcpLayer(tcp *layers.TCP, sig *signature.Signature) {

	ackNumber := tcp.Ack
	sequenceNumber := tcp.Seq
	urgentPointer := tcp.Urgent
	quirks := sig.Quirks

	// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
	// https://datatracker.ietf.org/doc/html/rfc791#section-3.1

	// sequence number is zero
	if quirks.SeqMinus {
		sequenceNumber = 0
	} else if sequenceNumber == 0 {
		sequenceNumber = uint32(rand.Intn(0xFFFFFFFF-1) + 1)
	}

	// ACK number is non-zero, but ACK flag not set
	if quirks.AckPlus {
		tcp.ACK = false
		if ackNumber == 0 {
			ackNumber = uint32(rand.Intn(0xFFFFFFFF-1) + 1)
		}

		// ACK number is zero, but ACK flag set
	} else if quirks.AckMinus {
		tcp.ACK = true
		ackNumber = 0
	}

	// URG pointer is non-zero, but URG flag not set
	if quirks.UptrPlus {
		tcp.URG = false
		if urgentPointer == 0 {
			urgentPointer = uint16(rand.Intn(0xFFFF-1) + 1)
		}
		// URG flag used
	} else if quirks.UrgfPlus {
		tcp.URG = true
	}

	tcp.Seq = sequenceNumber
	tcp.Ack = ackNumber
	tcp.Urgent = urgentPointer
	// PUSH flag used
	tcp.PSH = quirks.PushfPlus

	SpoofTcpOptions(tcp, sig)
	SpoofTcpWindow(tcp, sig)
}
