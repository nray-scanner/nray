package cmd

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"

	targetgeneration "github.com/nray-scanner/nray/core/targetGeneration"
	"github.com/nray-scanner/nray/events"
	"github.com/nray-scanner/nray/scanner"
	nraySchema "github.com/nray-scanner/nray/schemas"
	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rawPorts string
var rawTargets string
var scanUDP bool
var targetCount uint64
var scannedCount uint64
var timeout time.Duration
var outputFile string
var workers uint

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Starts a scan with parameters provided on the command line",
	Long: `If you want to initiate a quick and dirty simple scan without 
creating a configuration and attaching scanner nodes, the simple scan
is what you are looking for. Get the work done nmap-style like you are used to.`,
	Run: func(cmd *cobra.Command, args []string) {
		if rawTargets == "" { // scan from stdin

		}

		config := viper.New()
		config.Set("filename", outputFile)
		config.Set("overwriteExisting", true)

		targetChan := parseTargets()
		parsedPorts := parsePorts()
		scanChan := prepareScan(targetChan, parsedPorts)
		resultChan := make(chan (*scanner.PortscanResult), 100)
		scanFuncs := prepareScanFuncs(scanChan, resultChan)

		logfile := events.GetEventHandler("json-file")
		logfile.Configure(config)
		filechan := make(chan (*nraySchema.Event), 1000)
		go logfile.ProcessEventStream(filechan)
		stdout := events.GetEventHandler("terminal")
		stdout.Configure(viper.New())
		stdoutchan := make(chan (*nraySchema.Event), 1000)
		go stdout.ProcessEventStream(stdoutchan)

		go func(resultChan <-chan *scanner.PortscanResult) {
			for portscanResult := range resultChan {
				now, _ := ptypes.TimestampProto(time.Now())
				data := &nraySchema.Event{
					NodeID:      "0",
					NodeName:    "localscanner",
					Timestamp:   now,
					Scannername: "local",
					EventData: &nraySchema.Event_Result{
						Result: &nraySchema.ScanResult{
							Target: portscanResult.Target,
							Port:   portscanResult.Port,
							Result: &nraySchema.ScanResult_Portscan{
								Portscan: &nraySchema.PortScanResult{
									Scantype: portscanResult.Scantype,
									Target:   portscanResult.Target,
									Port:     portscanResult.Port,
									Open:     portscanResult.Open,
									Timeout:  uint32(portscanResult.Timeout / time.Millisecond),
								},
							},
						},
					},
				}
				filechan <- data
				stdoutchan <- data
			}
		}(resultChan)
		startScan(scanFuncs, resultChan)

		utils.CheckError(stdout.Close(), false)
		utils.CheckError(logfile.Close(), false)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&rawPorts, "ports", "p", "", "Ports to scan. A comma-separated list as well as ranges are supported.")
	scanCmd.PersistentFlags().StringVarP(&rawTargets, "targets", "t", "", "Targets to scan.")
	scanCmd.PersistentFlags().BoolVarP(&scanUDP, "udp", "u", false, "This flag switches to UDP scanning.")
	scanCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "", 1000*time.Millisecond, "Timeout for TCP connect.")
	scanCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "The file to write json output")
	scanCmd.PersistentFlags().UintVarP(&workers, "workers", "w", 1000, "How many workers to use for scanning.")
	scanCmd.MarkFlagRequired("ports")
	scanCmd.MarkFlagRequired("targets") // remove once stdin scanning is implemented
	log.SetFormatter(&utils.Formatter{})
}

func parseTargets() <-chan (string) {
	targetChan := make(chan (string), 500)
	go func(targets chan<- (string)) {
		for _, rawTarget := range strings.Split(rawTargets, ",") {
			if utils.Ipv4NetRegexpr.MatchString(rawTarget) { // An IPv4 network
				_, ipnet, err := net.ParseCIDR(rawTarget)
				targetCount += cidr.AddressCount(ipnet)
				utils.CheckError(err, true)
				ipStream := targetgeneration.GenerateIPStreamFromCIDR(ipnet, nil)
				for ip := range ipStream {
					targets <- ip.String()
				}
			} else if utils.Ipv4Regexpr.MatchString(rawTarget) { // An IPv4 address
				targetCount++
				targets <- rawTarget
			} else if utils.MayBeFQDN(rawTarget) { // Probably a FQDN
				targetCount++
				targets <- rawTarget
			} else {
				log.WithFields(log.Fields{
					"module": "cmd.scan",
					"src":    "parseTargets",
				}).Printf("This does not look like a valid target: %s", rawTarget)
			}
		}
		close(targets)
	}(targetChan)
	return targetChan
}

func parsePorts() []uint16 {
	if len(rawPorts) == 0 {
		log.Fatal("Port list is empty")
	}
	var parsedPorts []uint16
	if scanUDP {
		parsedPorts = targetgeneration.ParsePorts(strings.Split(rawPorts, ","), "udp")
	} else {
		parsedPorts = targetgeneration.ParsePorts(strings.Split(rawPorts, ","), "tcp")
	}
	return parsedPorts
}

func prepareScan(targetChan <-chan (string), ports []uint16) <-chan (*scanner.Target) {
	scanChan := make(chan (*scanner.Target), 1000)
	var proto string
	if scanUDP {
		proto = "UDP"
	} else {
		proto = "TCP"
	}
	for hostToScan := range targetChan {
		for _, port := range ports {
			t := &scanner.Target{
				Host:     hostToScan,
				Protocol: proto,
				Port:     uint32(port),
			}
			scanChan <- t
		}
	}
	close(scanChan)
	return scanChan
}

func startScan(funcChan <-chan (func()), resultChan chan<- *scanner.PortscanResult) {
	var wg sync.WaitGroup
	log.WithFields(log.Fields{
		"module": "cmd.scan",
		"src":    "startScan",
	}).Printf("Starting workers: %d", workers)
	for i := uint(0); i < workers; i++ {
		wg.Add(1)
		go func(queue <-chan func()) {
			for queuedTask := range queue {
				queuedTask()
			}
			wg.Done()
		}(funcChan)
	}
	wg.Wait()
	close(resultChan)
}

// prepareScanFuncs returns a channel where scan functions are sent over
// They are completely prepared and just have to be called
// This is a leightweight version of the larger implementation when using
// the full feature set
func prepareScanFuncs(targetChan <-chan (*scanner.Target), results chan<- *scanner.PortscanResult) <-chan func() {
	scannerconf := viper.New()
	scannerconf.Set("timeout", timeout)
	var tcpscanner = &scanner.TCPScanner{}
	tcpscanner.Configure(scannerconf)
	var udpscanner = &scanner.UDPScanner{}
	udpscanner.Configure(scannerconf)
	scanFuncs := make(chan func(), 100)

	go func(targetChan <-chan (*scanner.Target), results chan<- *scanner.PortscanResult) {
		for targetHost := range targetChan {
			if targetHost.Protocol == "UDP" {
				t := targetHost.Host
				port := targetHost.Port
				scanFuncs <- func() {
					result, err := scanner.UDPProtoScan(t, port, *udpscanner)
					utils.CheckError(err, false)
					if result != nil {
						results <- result
					}
				}
			} else { // Assume TCP default
				t := targetHost.Host
				port := targetHost.Port
				scanFuncs <- func() {
					result, err := scanner.TCPConnectIsOpen(t, port, timeout)
					utils.CheckError(err, false)
					if result != nil {
						results <- result
					}
				}
			}
		}
		close(scanFuncs)
	}(targetChan, results)

	return scanFuncs
}
