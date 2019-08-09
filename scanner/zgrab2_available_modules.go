package scanner

// ZGrab2AvailableScanners holds a list of all ZGrab2 scanners that are ported
// and may be used
var ZGrab2AvailableScanners = []string{"ssh", "http"}

// GetZGrab2Scanner returns an instance of the requested scanner
func GetZGrab2Scanner(ScannerName string) ProtocolScanner {
	switch ScannerName {
	case "ssh":
		return &SSHScanner{}
	case "http":
		return &HTTPScanner{}
	default:
		return nil
	}
}
