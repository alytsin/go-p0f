package signature

import (
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParse(t *testing.T) {

	var testData = []struct {
		signature string
		isErr     bool
		result    *Signature
	}{
		{":", true, nil},
		{"X:::::::", true, nil},               // ver
		{"*:X::::::", true, nil},              // ittl
		{"*:64:*:X::::", true, nil},           // mss
		{"*:64:*:65535:X:::", true, nil},      // wsize
		{"*:64:*:65535:*,0:X::", true, nil},   // olayout
		{"*:64:*:65535:*,0::X:", true, nil},   // quirks
		{"*:64:*:65535:*,0::df:X", true, nil}, // pclass
		{"*:64:*:65535:*,0::df:0", false, &Signature{
			IpVersion:          "*",
			InitialTTL:         64,
			MaximumSegmentSize: 65535,
			WindowSize: &WindowSize{
				WindowSize:          0,
				WindowSizeType:      WindowTypeAny,
				WindowScalingFactor: 0,
			},
			PayloadSize:   PayloadSizeZero,
			OptionsLayout: nil,
			Quirks:        &QuirkFlags{DF: true},
		}},
	}

	p := Parser{}
	for _, item := range testData {
		r, err := p.Parse(item.signature)
		assert.Equal(t, item.result, r)
		if item.isErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestParseWindowSize(t *testing.T) {
	var testData = []struct {
		src   string
		ws    *WindowSize
		isErr bool
	}{
		{"", nil, true},
		{",", nil, true},
		{"", nil, true},
		{"X", nil, true},
		{"0,", nil, true},
		{",0", nil, true},

		{"*,0", &WindowSize{WindowSize: 0, WindowSizeType: WindowTypeAny, WindowScalingFactor: 0}, false},
		{"*,5", &WindowSize{WindowSize: 0, WindowSizeType: WindowTypeAny, WindowScalingFactor: 5}, false},
		{"*,*", &WindowSize{WindowSize: 0, WindowSizeType: WindowTypeAny, WindowScalingFactor: WindowScaleFactorWildcardIntValue}, false},
		{"*,X", nil, true},
		{"*,", nil, true},

		{"100,0", &WindowSize{WindowSize: 100, WindowSizeType: WindowTypeNormal, WindowScalingFactor: 0}, false},
		{"-5,*", nil, true},
		{"0,*", nil, true},

		{"%5,0", &WindowSize{WindowSize: 5, WindowSizeType: WindowTypeMod, WindowScalingFactor: 0}, false},
		{"%,0", nil, true},
		{"%-1,0", nil, true},
		{"%X,0", nil, true},
		{"%-,0", nil, true},

		{"mss*5,0", &WindowSize{WindowSize: 5, WindowSizeType: WindowTypeMSS, WindowScalingFactor: 0}, false},
		{"mss*,0", nil, true},
		{"mss*X,0", nil, true},
		{"mss*0,0", nil, true},
		{"mss*-5,0", nil, true},
		{"mss*-,0", nil, true},

		{"mtu*5,0", &WindowSize{WindowSize: 5, WindowSizeType: WindowTypeMTU, WindowScalingFactor: 0}, false},
		{"mtu*,0", nil, true},
		{"mtu*X,0", nil, true},
		{"mtu*0,0", nil, true},
		{"mtu*-5,0", nil, true},
		{"mtu*-,0", nil, true},

		{"65536,*", nil, true},
		{"65535,0", &WindowSize{WindowSize: 65535, WindowSizeType: WindowTypeNormal, WindowScalingFactor: 0}, false},
	}

	p := Parser{}
	for _, item := range testData {
		r, err := p.parseWindowSize(item.src)
		assert.Equal(t, item.ws, r)
		if item.isErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestParsQuirks(t *testing.T) {
	p := Parser{}

	r, err := p.parseQuirks("")
	assert.Nil(t, r)
	assert.NoError(t, err)

	r, err = p.parseQuirks("xxx")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseQuirks("df,id+,id-,ecn,0+,flow,seq-,ack+,ack-,uptr+,urgf+,pushf+,ts1-,ts2+,opt+,exws,bad")
	assert.Equal(t, &QuirkFlags{
		DF:        true,
		IdPlus:    true,
		IdMinus:   true,
		ECN:       true,
		ZeroPlus:  true,
		Flow:      true,
		SeqMinus:  true,
		AckPlus:   true,
		AckMinus:  true,
		UptrPlus:  true,
		UrgfPlus:  true,
		PushfPlus: true,
		TsMinus:   true,
		TsPlus:    true,
		OptPlus:   true,
		EXWS:      true,
		Bad:       true,
	}, r)
	assert.NoError(t, err)
}

func TestParseMaximumSegmentSize(t *testing.T) {
	p := Parser{}

	r, err := p.parseMaximumSegmentSize("*")
	assert.Equal(t, MaximumSegmentSizeWildcardIntValue, r)
	assert.NoError(t, err)

	r, err = p.parseMaximumSegmentSize("5")
	assert.Equal(t, 5, r)
	assert.NoError(t, err)

	r, err = p.parseMaximumSegmentSize("0")
	assert.Equal(t, 0, r)
	assert.NoError(t, err)

	r, err = p.parseMaximumSegmentSize("xxxx")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseMaximumSegmentSize("-5")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseMaximumSegmentSize("")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseMaximumSegmentSize("11111111")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

}

func TestParseInitialTTL(t *testing.T) {
	p := Parser{}

	r, err := p.parseInitialTTL("")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseInitialTTL("a")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseInitialTTL("6-")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseInitialTTL("6")
	assert.Equal(t, 6, r)
	assert.NoError(t, err)

	r, err = p.parseInitialTTL("-6")
	assert.Equal(t, 0, r)
	assert.Error(t, err)

	r, err = p.parseInitialTTL("-")
	assert.Equal(t, 0, r)
	assert.Error(t, err)
}

func TestParsePayloadSize(t *testing.T) {

	p := Parser{}

	r, err := p.parsePayloadSize("XXX")
	assert.Equal(t, PayloadSize(""), r)
	assert.Error(t, err)

	r, err = p.parsePayloadSize("")
	assert.Equal(t, PayloadSize(""), r)
	assert.Error(t, err)

	r, err = p.parsePayloadSize("*")
	assert.Equal(t, PayloadSizeAny, r)
	assert.NoError(t, err)

	r, err = p.parsePayloadSize("+")
	assert.Equal(t, PayloadSizeNonZero, r)
	assert.NoError(t, err)

	r, err = p.parsePayloadSize("0")
	assert.Equal(t, PayloadSizeZero, r)
	assert.NoError(t, err)

}

func TestParseIpVersion(t *testing.T) {

	p := Parser{}

	r, err := p.parseIpVersion("XXX")
	assert.Equal(t, IpVersion(""), r)
	assert.Error(t, err)

	r, err = p.parseIpVersion("")
	assert.Equal(t, IpVersion(""), r)
	assert.Error(t, err)

	r, err = p.parseIpVersion("4")
	assert.Equal(t, IpVersion4, r)
	assert.NoError(t, err)

	r, err = p.parseIpVersion("6")
	assert.Equal(t, IpVersion6, r)
	assert.NoError(t, err)

	r, err = p.parseIpVersion("*")
	assert.Equal(t, IpVersionAny, r)
	assert.NoError(t, err)

}

func TestParseOptions(t *testing.T) {
	p := Parser{}

	r, err := p.parseOptions("eol,nop,mss,ws,sok,sack,ts,eol+1")
	assert.Equal(t, []layers.TCPOptionKind{
		layers.TCPOptionKindEndList, layers.TCPOptionKindNop, layers.TCPOptionKindMSS, layers.TCPOptionKindWindowScale,
		layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindSACK, layers.TCPOptionKindTimestamps,
		layers.TCPOptionKindEndList, layers.TCPOptionKindEndList,
	}, r)
	assert.NoError(t, err)

	r, err = p.parseOptions("eol+1")
	assert.Equal(t, []layers.TCPOptionKind{layers.TCPOptionKindEndList, layers.TCPOptionKindEndList}, r)
	assert.NoError(t, err)

	r, err = p.parseOptions("eol+0")
	assert.Equal(t, []layers.TCPOptionKind{layers.TCPOptionKindEndList}, r)
	assert.NoError(t, err)

	r, err = p.parseOptions("xxx")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseOptions("eol+")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseOptions("eolX")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseOptions("eol+X")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseOptions("eol-5")
	assert.Nil(t, r)
	assert.Error(t, err)

	r, err = p.parseOptions("")
	assert.Nil(t, r)
	assert.NoError(t, err)

}
