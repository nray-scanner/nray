package core

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
)

func TestInitGlobalConfig(t *testing.T) {
	globalConfigPositive(t)
}

func globalConfigPositive(t *testing.T) {
	viper.SetConfigType("yaml")
	testdata := []byte(`listen: [8601, '80', "443"]`)
	parsedShouldBe := []uint32{8601, 80, 443}
	viper.ReadConfig(bytes.NewBuffer(testdata))
	err := InitGlobalServerConfig()
	if err != nil {
		t.Fail()
	}
	if len(CurrentConfig.ListenPorts) != len(parsedShouldBe) {
		t.Fail()
	}
	for pos, elem := range CurrentConfig.ListenPorts {
		if elem != parsedShouldBe[pos] {
			t.Fail()
		}
	}
}
