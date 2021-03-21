package targetgeneration

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/nray-scanner/nray/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var availableBackends = []string{"standard", "certificatetransparency", "ldap"}

// getBackend returns the correct backend for a backend name
func getBackend(backendName string) targetGeneratorBackend {
	switch backendName {
	case "standard":
		return &standardTGBackend{}
	default:
		return nil
	}
}

// AnyTargets is the most abstract type holding information
// regarding targets. Any number of hosts, networks, ports etc.
// is allowed
type AnyTargets struct {
	RemoteHosts []string
	TCPPorts    []uint32
	UDPPorts    []uint32
}

// TargetCount returns the number of targets, meaning individual ports on individual systems
func (at *AnyTargets) TargetCount() uint64 {
	return uint64(len(at.RemoteHosts) * (len(at.TCPPorts) + len(at.UDPPorts)))
}

// TargetGenerator is the type that unifies all backends and provides
// central access to all generated targets
type TargetGenerator struct {
	targetChannels []<-chan AnyTargets
	targetChan     chan AnyTargets
	targetCount    uint64
}

// Init takes the target generation subtree of the configuration
// and sets up the TargetGenerator to receive targets from
func (tg *TargetGenerator) Init(config *viper.Viper) {
	tg.targetChan = make(chan AnyTargets, config.GetInt("buffersize"))
	for _, availableBackend := range availableBackends {
		// For each backend enabled
		if config.GetBool(fmt.Sprintf("%s.enabled", availableBackend)) {
			// Get a new instance of the backend
			backend := getBackend(availableBackend)
			// Supply config
			err := backend.configure(config.Sub(availableBackend))
			utils.CheckError(err, true)
			tg.targetCount, err = backend.targetCount()
			utils.CheckError(err, false)
			// Append channel to slice holding all channels that are sending work
			tg.targetChannels = append(tg.targetChannels, backend.receiveTargets())
		}
	}
	go tg.zipChannels()
}

// GetTargetChan is used to expose a read-only channel to the core
func (tg *TargetGenerator) GetTargetChan() <-chan AnyTargets {
	return tg.targetChan
}

// TargetCount returns the total target count of this target generator.
func (tg *TargetGenerator) TargetCount() uint64 {
	return tg.targetCount
}

// zipChannels reads from all channels supplying targets and sends work over a single
// channel where it is consumed from the core.
// It is supposed to be called only once as goroutine from tg.Init()
// Closed channels are removed from the slice.
// If the slice becomes empty, the target channel core reads from is closed
func (tg *TargetGenerator) zipChannels() {
outer:
	for len(tg.targetChannels) > 0 {
		for pos, channel := range tg.targetChannels {
			elem, ok := <-channel
			// Channel is closed, remove from slice
			if !ok {
				// Don't ask, see https://github.com/golang/go/wiki/SliceTricks
				copy(tg.targetChannels[pos:], tg.targetChannels[pos+1:])
				tg.targetChannels[len(tg.targetChannels)-1] = nil // or the zero value of T
				tg.targetChannels = tg.targetChannels[:len(tg.targetChannels)-1]

				// After modifying the slice that is currently iterated over it may be wise to start over from the beginning
				continue outer
			}
			tg.targetChan <- elem
		}
	}
	close(tg.targetChan)
}

// targetGeneratorBackend is the interface that has to be implemented in order to
// supply targets for the TargetGenerator
type targetGeneratorBackend interface {
	configure(*viper.Viper) error
	receiveTargets() <-chan AnyTargets
	targetCount() (uint64, error)
}

// Taken from https://www.rosettacode.org/wiki/Remove_duplicate_elements#Map_solution
func uniq(list []uint16) []uint16 {
	uniqueSet := make(map[uint16]bool, len(list))
	for _, x := range list {
		uniqueSet[x] = true
	}
	result := make([]uint16, 0, len(uniqueSet))
	for x := range uniqueSet {
		result = append(result, x)
	}
	return result
}

// GetNmapTopTCPPorts returns an array containing the topN TCP ports
func GetNmapTopTCPPorts(topN uint) []uint16 {
	if topN > uint(len(TopTCPPorts)) {
		topN = uint(len(TopTCPPorts))
	}
	return TopTCPPorts[0:int(topN)]
}

// GetNmapTopUDPPorts returns an array containing the topN UDP ports
func GetNmapTopUDPPorts(topN uint) []uint16 {
	if topN > uint(len(TopUDPPorts)) {
		topN = uint(len(TopUDPPorts))
	}
	return TopUDPPorts[0:int(topN)]
}

// GenerateIPStreamFromCIDR uses the ZMap algorithm to expand a CIDR network.
// A blacklist may be specified and hosts contained in there are omitted.
// Returns a stream of hosts, which is closed when the network has been completely expanded.
func GenerateIPStreamFromCIDR(ipnet *net.IPNet, blacklist *NrayBlacklist) <-chan net.IP {
	if blacklist == nil {
		blacklist = NewBlacklist()
	}
	// size is arbitrary, 50 should be enough avoid that the channel empties during operation
	returnChan := make(chan net.IP, 50)

	// Generate target asynchronously
	go func(returnChan chan<- net.IP, ipnet *net.IPNet, blacklist *NrayBlacklist) {
		// Set up parameters for the sharding algorithm
		// There is a first and a current number that are mapped to the n-th IP in the network
		// A loop is calling next() to generate a new currNum and sending it to the work chan
		// until currNum equals first again - then there was a complete run through the circle and
		// the algoritm is done
		var firstNum, currNum uint64
		group := getGroup(cidr.AddressCount(ipnet))
		// Masscan and ZMap support user-controlled seeds, using current time should be enough
		// until somebody comes up with the requirement to manually seed.
		cycle := makeCycle(group, time.Now().UTC().UnixNano())
		firstNum = first(&cycle)
		currNum = firstNum
		// Don't always start with 1
		next(&cycle, &currNum)
		// Remember to fix firstNum for break condition later
		firstNum = currNum

		// Generation happens here
		for {
			nextHost, _ := cidr.Host(ipnet, int(currNum))
			if nextHost != nil && !blacklist.IsIPBlacklisted(nextHost.String()) {
				returnChan <- nextHost
			}
			next(&cycle, &currNum)
			if currNum == 0 { // we had 0, so stop now
				break
			}
			if currNum == firstNum { // we did a full run through the cycle, but 0 is still missing
				currNum = 0
			}
		}
		log.WithFields(log.Fields{
			"module": "targetgeneration.targetGenerator",
			"src":    "GenerateIPStreamFromCIDR",
		}).Debug("Closing returnChan")
		close(returnChan)
	}(returnChan, ipnet, blacklist)

	return returnChan
}

// GeneratePortStream takes a list of ports and returns them in arbitrary order over a channel
func GeneratePortStream(ports []uint16) <-chan uint16 {
	// size is arbitrary, 50 should be enough avoid that the channel empties during operation
	returnChan := make(chan uint16, 50)

	// Shuffle slice
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(ports), func(i, j int) {
		ports[i], ports[j] = ports[j], ports[i]
	})

	// ports are sent back over the channel asynchronously
	go func(returnChan chan<- uint16, ports []uint16) {
		for _, port := range ports {
			returnChan <- port
		}
		close(returnChan)
	}(returnChan, ports)

	return returnChan
}

// ParsePorts takes the a list of target strings supplied by the user
// and tries to parse them into a slice of uint32s
// Errors are sent back over errorChan
func ParsePorts(rawPorts []string, proto string) []uint16 {
	ports := make([]uint16, 0)
	portRangeRegexpr := regexp.MustCompile(utils.RegexPortRange)
	topPortsRegexpr := regexp.MustCompile(utils.RegexTopPorts)
	thousandNumberRegexp := regexp.MustCompile(utils.RegexThousandNumber)
	for _, candidate := range rawPorts {
		// A single port
		parsed, err := strconv.ParseUint(candidate, 10, 32)
		if err == nil && parsed < math.MaxUint16 {
			ports = append(ports, uint16(parsed))
			continue
		} else if portRangeRegexpr.MatchString(candidate) { // A port range. Split, sort, flatten.
			splitted := strings.Split(candidate, "-")
			first, err := strconv.ParseUint(splitted[0], 10, 32)
			if err == nil && first <= math.MaxUint16 {
				second, err := strconv.ParseUint(splitted[1], 10, 32)
				if err == nil && second <= math.MaxUint16 {
					var start, end uint16
					if first <= second {
						start = uint16(first)
						end = uint16(second)
					} else {
						start = uint16(second)
						end = uint16(first)
					}
					for i := start; i <= end; i++ {
						ports = append(ports, i)
						if i == math.MaxUint16 { // Otherwise there is a nasty overflow causing a memory leak until you get killed by OOM
							break
						}
					}
					continue
				}
			}
		} else if topPortsRegexpr.MatchString(candidate) { // A toplist
			topN, err := strconv.ParseUint(thousandNumberRegexp.FindString(candidate), 10, 32)
			utils.CheckError(err, true)
			if proto == "udp" {
				ports = append(ports, GetNmapTopUDPPorts(uint(topN))...)
			} else {
				ports = append(ports, GetNmapTopTCPPorts(uint(topN))...)
			}
			continue
		} else if candidate == "all" {
			for i := uint16(1); i <= math.MaxUint16; i++ {
				ports = append(ports, i)
				if i == math.MaxUint16 { // Otherwise there is a nasty overflow causing a memory leak until you get killed by OOM
					break
				}
			}
		} else {
			log.Warningf("Can't parse port list %s, skipping.", candidate)
		}
	}

	return uniq(ports)
}

// chunkPorts creates a slice of AnyTargets that contain all provided hosts with the specified port chunkings
func chunkPorts(hosts []string, tcpports []uint16, udpports []uint16, maxTCPPorts uint, maxUDPPorts uint) []AnyTargets {
	targets := make([]AnyTargets, 0)

	// Get fresh port streams
	tcpPortStream := GeneratePortStream(tcpports)
	udpPortStream := GeneratePortStream(udpports)

	// As long as both port streams are not consumed, create new AnyTargets containing the
	// host list and the targets.
	for tcpPortStream != nil || udpPortStream != nil {
		tcpPorts := make([]uint32, 0)
		udpPorts := make([]uint32, 0)
		for numTCPPort := uint(0); numTCPPort < maxTCPPorts; numTCPPort++ {
			if tcpPortStream == nil {
				break
			}
			tcpPort, ok := <-tcpPortStream
			if !ok {
				tcpPortStream = nil
				break
			}
			tcpPorts = append(tcpPorts, uint32(tcpPort))
		}
		for numUDPPort := uint(0); numUDPPort < maxUDPPorts; numUDPPort++ {
			if udpPortStream == nil {
				break
			}
			udpPort, ok := <-udpPortStream
			if !ok {
				udpPortStream = nil
				break
			}
			udpPorts = append(udpPorts, uint32(udpPort))
		}
		if len(tcpPorts) == 0 && len(udpPorts) == 0 {
			continue
		}
		newTarget := AnyTargets{
			RemoteHosts: hosts,
			TCPPorts:    tcpPorts,
			UDPPorts:    udpPorts,
		}
		targets = append(targets, newTarget)
	}
	return targets
}
