package utils

import (
	"bytes"
	"os"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// CheckError provides general error handling
func CheckError(err error, critical bool) {
	if err != nil {
		if critical {
			log.WithFields(log.Fields{
				"module": "utils.errorhandling",
				"src":    "CheckError",
			}).Errorf("An error occured: %v", err.Error())
			os.Exit(1)
		}
		log.WithFields(log.Fields{
			"module": "utils.errorhandling",
			"src":    "CheckError",
		}).Warningf("An error occured: %v", err.Error())
	}
}

// DbgGetGID returns the number of the goroutine calling this function. DEBUG ONLY!!
func DbgGetGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}
