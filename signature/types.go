package signature

import "github.com/google/gopacket/layers"

type IpVersion string
type PayloadSize string
type WindowType int

const (
	MaximumSegmentSizeWildcardIntValue = -1
	WindowScaleFactorWildcardIntValue  = -1

	IpVersion4   IpVersion = "4"
	IpVersion6   IpVersion = "6"
	IpVersionAny IpVersion = "*"

	PayloadSizeZero    PayloadSize = "0"
	PayloadSizeNonZero PayloadSize = "+"
	PayloadSizeAny     PayloadSize = "*"

	WindowTypeNormal WindowType = 0
	WindowTypeAny    WindowType = 1
	WindowTypeMod    WindowType = 2
	WindowTypeMSS    WindowType = 3
	WindowTypeMTU    WindowType = 4

	optionNameEndList       string = "eol"
	optionNameNop           string = "nop"
	optionNameMSS           string = "mss"
	optionNameWindowScale   string = "ws"
	optionNameSACKPermitted string = "sok"
	optionNameSACK          string = "sack"
	optionNameTimestamps    string = "ts"

	quirkDF       string = "df"   // "don't fragment" set (probably PMTUD); ignored for IPv6
	quirkIdPlus   string = "id+"  // DF set but IPID non-zero; ignored for IPv6
	quirkIdMinus  string = "id-"  // DF not set but IPID is zero; ignored for IPv6
	quirkECN      string = "ecn"  // explicit congestion notification support
	quirkZeroPlus string = "0+"   // "must be zero" field not zero; ignored for IPv6
	quirkFlow     string = "flow" // non-zero IPv6 flow ID; ignored for IPv4

	quirkSeqMinus  string = "seq-"   // sequence number is zero
	quirkAckPlus   string = "ack+"   // ACK number is non-zero, but ACK flag not set
	quirkAckMinus  string = "ack-"   // ACK number is zero, but ACK flag set
	quirkUptrPlus  string = "uptr+"  // URG pointer is non-zero, but URG flag not set
	quirkUrgfPlus  string = "urgf+"  // URG flag used
	quirkPushfPlus string = "pushf+" // PUSH flag used

	quirkTsMinus string = "ts1-" // own timestamp specified as zero
	quirkTsPlus  string = "ts2+" // non-zero peer timestamp on initial SYN
	quirkOptPlus string = "opt+" // trailing non-zero data in options segment
	quirkEXWS    string = "exws" // excessive window scaling factor (> 14)
	quirkBad     string = "bad"  // malformed TCP options
	// match a packet sent from the Linux network stack
	// (IP.id field equal to TCP.ts1 xor TCP.seq_num).
	// Note that this quirk is not part of the original p0f signature format;
	// we decided to add it since we found it useful.
	// https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler
	quirkLinux string = "linux"
)

type WindowSize struct {
	WindowSize          uint16
	WindowSizeType      WindowType
	WindowScalingFactor int
}

type QuirkFlags struct {
	DF        bool
	IdPlus    bool
	IdMinus   bool
	ECN       bool
	ZeroPlus  bool
	Flow      bool
	SeqMinus  bool
	AckPlus   bool
	AckMinus  bool
	UptrPlus  bool
	UrgfPlus  bool
	PushfPlus bool
	TsMinus   bool
	TsPlus    bool
	OptPlus   bool
	EXWS      bool
	Bad       bool
}

type Signature struct {
	IpVersion  IpVersion
	InitialTTL int
	// Length of "Options" field of IP v4 structure
	// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Options
	//OptionLength       int
	MaximumSegmentSize int
	WindowSize         *WindowSize
	PayloadSize        PayloadSize
	OptionsLayout      []layers.TCPOptionKind
	Quirks             *QuirkFlags
}
