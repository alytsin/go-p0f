package signature

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"strconv"
	"strings"
)

// https://lcamtuf.coredump.cx/p0f3/README
type Parser struct {
}

func (parser *Parser) Parse(signature string) (*Signature, error) {

	ss := strings.Split(signature, ":")
	if len(ss) != 8 {
		return nil, fmt.Errorf("invalid signature '%s'", signature)
	}

	var err error
	result := Signature{}

	result.IpVersion, err = parser.parseIpVersion(ss[0])
	if err != nil {
		return nil, err
	}

	result.InitialTTL, err = parser.parseInitialTTL(ss[1])
	if err != nil {
		return nil, err
	}

	result.MaximumSegmentSize, err = parser.parseMaximumSegmentSize(ss[3])
	if err != nil {
		return nil, err
	}

	result.WindowSize, err = parser.parseWindowSize(ss[4])
	if err != nil {
		return nil, err
	}

	result.OptionsLayout, err = parser.parseOptions(ss[5])
	if err != nil {
		return nil, err
	}

	result.Quirks, err = parser.parseQuirks(ss[6])
	if err != nil {
		return nil, err
	}

	result.PayloadSize, err = parser.parsePayloadSize(ss[7])
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (parser *Parser) parseWindowSize(ws string) (*WindowSize, error) {

	errorMessage := fmt.Errorf("invalid windows size format '%s'", ws)
	windowData := strings.Split(ws, ",")

	if len(windowData) != 2 {
		return nil, errorMessage
	}

	wsize := windowData[0]
	scale := windowData[1]

	if len(wsize) == 0 || len(scale) == 0 {
		return nil, errorMessage
	}

	var wScale int

	if scale == "*" {
		wScale = WindowScaleFactorWildcardIntValue
	} else {
		n, err := strconv.Atoi(scale)
		if err != nil {
			return nil, errorMessage
		}
		wScale = n
	}

	if wsize == "*" {
		return &WindowSize{
			WindowSize:          0,
			WindowSizeType:      WindowTypeAny,
			WindowScalingFactor: wScale,
		}, nil
	}

	n, err := strconv.Atoi(wsize)
	if err == nil {
		if n <= 0 || n > 0xFFFF {
			return nil, errorMessage
		}
		return &WindowSize{
			WindowSize:          uint16(n),
			WindowSizeType:      WindowTypeNormal,
			WindowScalingFactor: wScale,
		}, nil
	}

	var valuePart string
	var wType WindowType

	if len(wsize) >= 5 && wsize[3] == '*' {
		if wsize[0:3] == "mss" {
			valuePart = wsize[4:]
			wType = WindowTypeMSS
		} else if wsize[0:3] == "mtu" {
			valuePart = wsize[4:]
			wType = WindowTypeMTU
		}
	} else if len(wsize) >= 2 && wsize[0] == '%' {
		valuePart = wsize[1:]
		wType = WindowTypeMod
	}

	var wSize uint16
	if len(valuePart) > 0 {
		i, err := strconv.Atoi(valuePart)
		if err != nil || i <= 0 || i > 0xFFFF {
			return nil, errorMessage
		}
		wSize = uint16(i)
	} else {
		return nil, errorMessage
	}

	return &WindowSize{
		WindowSize:          wSize,
		WindowSizeType:      wType,
		WindowScalingFactor: wScale,
	}, nil

}

func (parser *Parser) parseMaximumSegmentSize(s string) (int, error) {

	errorMsg := "invalid maximum segment size value '%s'"

	if s == "*" {
		return MaximumSegmentSizeWildcardIntValue, nil
	}

	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf(errorMsg, s)
	}

	if i < 0 || i > 0xFFFFF {
		return 0, fmt.Errorf(errorMsg, s)
	}

	return i, nil
}

func (parser *Parser) parseInitialTTL(s string) (int, error) {

	errorMsg := "invalid initial TTL value '%s'"

	if len(s) > 0 {
		i, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf(errorMsg, s)
		}

		if i <= 0 {
			return 0, fmt.Errorf(errorMsg, s)
		}

		return i, nil
	}

	return 0, fmt.Errorf(errorMsg, s)
}

func (parser *Parser) parseQuirks(s string) (*QuirkFlags, error) {

	if s == "" {
		return nil, nil
	}

	quirks := strings.Split(s, ",")

	flags := QuirkFlags{}
	for _, quirk := range quirks {
		switch quirk {
		case quirkDF:
			flags.DF = true
		case quirkIdPlus:
			flags.IdPlus = true
		case quirkIdMinus:
			flags.IdMinus = true
		case quirkECN:
			flags.ECN = true
		case quirkZeroPlus:
			flags.ZeroPlus = true
		case quirkFlow:
			flags.Flow = true
		case quirkSeqMinus:
			flags.SeqMinus = true
		case quirkAckPlus:
			flags.AckPlus = true
		case quirkAckMinus:
			flags.AckMinus = true
		case quirkUptrPlus:
			flags.UptrPlus = true
		case quirkUrgfPlus:
			flags.UrgfPlus = true
		case quirkPushfPlus:
			flags.PushfPlus = true
		case quirkTsMinus:
			flags.TsMinus = true
		case quirkTsPlus:
			flags.TsPlus = true
		case quirkOptPlus:
			flags.OptPlus = true
		case quirkEXWS:
			flags.EXWS = true
		case quirkBad:
			flags.Bad = true
		default:
			return nil, fmt.Errorf("invalid quirk '%s'", quirk)
		}
	}

	return &flags, nil
}

func (parser *Parser) parsePayloadSize(s string) (PayloadSize, error) {

	switch s {
	case "0":
		return PayloadSizeZero, nil
	case "+":
		return PayloadSizeNonZero, nil
	case "*":
		return PayloadSizeAny, nil
	}

	return "", fmt.Errorf("invalid payload size value '%s'", s)
}

func (parser *Parser) parseIpVersion(s string) (IpVersion, error) {
	switch s {
	case "4":
		return IpVersion4, nil
	case "6":
		return IpVersion6, nil
	case "*":
		return IpVersionAny, nil
	}
	return "", fmt.Errorf("invalid IP version '%s'", s)
}

func (parser *Parser) parseOptions(s string) ([]layers.TCPOptionKind, error) {

	if s == "" {
		return nil, nil
	}

	opts := strings.Split(s, ",")

	errorMsg := "invalid option '%s'"
	options := make([]layers.TCPOptionKind, 0)

	for _, opt := range opts {

		if len(opt) >= 5 {
			// explicit end of options, followed by n bytes of padding
			if opt[:4] == (optionNameEndList + "+") {
				i, err := strconv.Atoi(opt[4:])
				if err != nil {
					return nil, fmt.Errorf(errorMsg, opt)
				}
				options = append(options, layers.TCPOptionKindEndList)
				for n := 1; n <= i; n++ {
					options = append(options, layers.TCPOptionKindEndList)
				}
				continue
			}
			return nil, fmt.Errorf(errorMsg, opt)
		}

		switch opt {
		case optionNameEndList:
			options = append(options, layers.TCPOptionKindEndList)
		case optionNameMSS:
			options = append(options, layers.TCPOptionKindMSS)
		case optionNameNop:
			options = append(options, layers.TCPOptionKindNop)
		case optionNameWindowScale:
			options = append(options, layers.TCPOptionKindWindowScale)
		case optionNameSACKPermitted:
			// selective ACK permitted
			options = append(options, layers.TCPOptionKindSACKPermitted)
		case optionNameSACK:
			// selective ACK (should not be seen)
			options = append(options, layers.TCPOptionKindSACK)
		case optionNameTimestamps:
			options = append(options, layers.TCPOptionKindTimestamps)
		default:
			return nil, fmt.Errorf(errorMsg, opt)
		}
	}

	return options, nil
}
