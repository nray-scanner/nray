package core

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/nray-scanner/nray/utils"
	"github.com/spf13/viper"
)

func TestInitGlobalConfig(t *testing.T) {
	globalConfigPositive(t)
}

func globalConfigPositive(t *testing.T) {
	testdata := []byte(`listen: [8601, '80', "443"]`)
	parsedShouldBe := []uint32{8601, 80, 443}
	v := viper.New()
	v.SetConfigType("yaml")

	v.ReadConfig(bytes.NewBuffer(testdata))
	utils.ApplyDefaultConfig(v)
	err := InitGlobalServerConfig(v)
	if err != nil {
		fmt.Println(err.Error())
		t.Errorf("Unable to init global server config")
	}
	if len(CurrentConfig.ListenPorts) != len(parsedShouldBe) {
		t.Errorf("Not listening on all ports that should be listened on")
	}
	for pos, elem := range CurrentConfig.ListenPorts {
		if elem != parsedShouldBe[pos] {
			t.Errorf("Listening on wrong port")
		}
	}
}
