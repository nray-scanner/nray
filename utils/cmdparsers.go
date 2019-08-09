package utils

import "fmt"

// ParseTargets parses the string given by the user into
// a format that can be used later on
func ParseTargets(rawTargets []string) (string, error) {
	if len(rawTargets) != 1 {
		if len(rawTargets) == 0 {
			return "", fmt.Errorf("No targets specified")
		}
		return "", fmt.Errorf("Target format wrong")

	}
	// TODO: implement actual parsing, change type or return value
	return rawTargets[0], nil
}

// ParsePorts parses the string given by the user into a list
// of ports to scan
func ParsePorts(rawPorts string) ([]uint32, error) {
	// TODO: implement parsing logic
	return []uint32{80}, nil
}
