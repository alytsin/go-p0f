package p0f

import (
	"encoding/binary"
	"github.com/alytsin/go-p0f/signature"
	"github.com/google/gopacket/layers"
	"math"
	"math/rand"
)

func SpoofTcpOptions(tcp *layers.TCP, sig *signature.Signature) {

	var mssHint uint16 = 0
	var mssFound = false

	var ts1Hint uint32 = 0
	var ts2Hint uint32 = 0
	var tsFound = false

	var wsHint uint8 = 0
	var wsFound = false

	for _, option := range tcp.Options {
		switch option.OptionType {

		// https://www.cloudflare.com/learning/network-layer/what-is-mss/
		// https://en.wikipedia.org/wiki/Maximum_segment_size
		// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Maximum_segment_size
		// https://www.geeksforgeeks.org/maximum-segment-size/
		case layers.TCPOptionKindMSS:
			if len(option.OptionData) >= 2 {
				mssFound = true
				mssHint = binary.BigEndian.Uint16(option.OptionData)
			}
		case layers.TCPOptionKindTimestamps:
			tsFound = true
			ts1Hint = binary.BigEndian.Uint32(option.OptionData[:4])
			ts2Hint = binary.BigEndian.Uint32(option.OptionData[4:8])
		case layers.TCPOptionKindWindowScale:
			wsFound = true
			wsHint = option.OptionData[0]
		}
	}

	var newOptions []layers.TCPOption

	for _, sigOption := range sig.OptionsLayout {
		switch sigOption {
		case layers.TCPOptionKindWindowScale:
			var ws uint8

			if sig.WindowSize.WindowScalingFactor == signature.WindowScaleFactorWildcardIntValue {

				var maxWs uint8 = 0xFF

				// excessive window scaling factor (> 14)
				if sig.Quirks.EXWS {
					if wsFound && wsHint > 14 && wsHint < maxWs {
						ws = wsHint
					} else {
						ws = uint8(rand.Int31n(0xFF-15) + 15)
					}
				} else {
					if wsFound {
						ws = wsHint
					} else {
						ws = uint8(rand.Int31n(14-1) + 1)
					}
				}

			} else {
				ws = uint8(sig.WindowSize.WindowScalingFactor)
			}

			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{ws},
			})

		case layers.TCPOptionKindMSS:

			mss := make([]byte, 2)

			if sig.MaximumSegmentSize == signature.MaximumSegmentSizeWildcardIntValue {
				var maxMss uint16 = 0xFFFF

				// in case of windows size in signature has format "mss*X"
				if sig.WindowSize.WindowSizeType == signature.WindowTypeMSS {
					maxMss = uint16(math.Floor(0xFFFF / float64(sig.WindowSize.WindowSize)))
				}

				// https://datatracker.ietf.org/doc/html/rfc791#section-3.1
				// The number 576 is selected to allow a reasonable sized data block to
				// be transmitted in addition to the required header information.
				// Since TCP uses 40 bytes of overhead, then the minimum MSS is 536 bytes.
				var minMss uint16 = 536

				if mssFound && mssHint >= minMss && mssHint <= maxMss {
					binary.BigEndian.PutUint16(mss, mssHint)
				} else {
					// TODO: test this subtraction
					binary.BigEndian.PutUint16(mss, uint16(rand.Int31n(int32(maxMss-minMss))+int32(minMss)))
				}

			} else {
				// exact MSS value from signature
				binary.BigEndian.PutUint16(mss, uint16(sig.MaximumSegmentSize))
			}

			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   mss,
			})

		case layers.TCPOptionKindTimestamps:

			// own timestamp specified as zero
			if sig.Quirks.TsMinus {
				ts1Hint = 0
			} else if !tsFound || ts1Hint == 0 {
				// just random values
				ts1Hint = uint32(rand.Int31n((0xFFFFFFFF - 0xFF) + 0xFF))
			}

			// non-zero peer timestamp on initial SYN
			if sig.Quirks.TsPlus && tcp.SYN {
				if !tsFound || ts2Hint == 0 {
					// just random values
					ts2Hint = uint32(rand.Int31n((0xFFFFFFFF - 0xFF) + 0xFF))
				}
			} else {
				ts2Hint = 0
			}

			tsData := make([]byte, 8)
			binary.BigEndian.PutUint32(tsData, ts1Hint)
			binary.BigEndian.PutUint32(tsData[4:], ts2Hint)

			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindTimestamps,
				OptionLength: 10,
				OptionData:   tsData,
			})

		case layers.TCPOptionKindSACKPermitted:
			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			})
		case layers.TCPOptionKindNop:
			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindNop,
				OptionLength: 0,
			})
		case layers.TCPOptionKindEndList:
			newOptions = append(newOptions, layers.TCPOption{
				OptionType:   layers.TCPOptionKindEndList,
				OptionLength: 0,
			})
		}
	}

	tcp.Options = newOptions
}
