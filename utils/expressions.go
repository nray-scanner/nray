package utils

import (
	"regexp"
	"strings"
)

// RegexIPv4 matches on an IPv4 address
const RegexIPv4 = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

// RegexNetIPv4 matches on an CIDR IPv4 network specification
const RegexNetIPv4 = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\/(3[0-2]|[1-2][0-9]|[0-9]))$"

// RegexPortRange matches strings of the form "{number}-{number}" where number are 1 to 5 digits
const RegexPortRange = "^[0-9]{1,5}-[0-9]{1,5}$"

// RegexTopPorts matches strings like "top25" or "Top2500"
const RegexTopPorts = "^[tT]op[-]?[0-9]{1,4}$"

// RegexThousandNumber matches all numbers between 1000 and 9999 plus 0000
const RegexThousandNumber = "[0-9]{1,4}"

// Ipv4Regexpr is the above IPv4 regex, already conveniently compiled
var Ipv4Regexpr = regexp.MustCompile(RegexIPv4)

// Ipv4NetRegexpr is the above IPv4 CIDR regex, already conveniently compiled
var Ipv4NetRegexpr = regexp.MustCompile(RegexNetIPv4)

// MayBeFQDN returns true if there are no slashes or colons in the string
func MayBeFQDN(toCheck string) bool {
	// If there is no scheme and no port, we may be good
	// Simply check if there are any ":" or "/" in the string,
	// otherwise give it a try
	return !strings.ContainsAny(toCheck, ":/")
}
