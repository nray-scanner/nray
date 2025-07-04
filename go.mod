module github.com/nray-scanner/nray

go 1.23.0

toolchain go1.24.2

require (
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/bitfield/script v0.24.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/golang/protobuf v1.5.4
	github.com/golang/time v0.12.0
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/zmap/go-iptree v0.0.0-20210731043055-d4e632617837
	nanomsg.org/go/mangos/v2 v2.0.8
)

require (
	github.com/asergeyev/nradix v0.0.0-20220715161825-e451993e425c // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/itchyny/gojq v0.12.17 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.9.2 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	mvdan.cc/sh/v3 v3.11.0 // indirect
)

replace github.com/golang/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4

replace golang.org/x/time => github.com/golang/time v0.0.0-20190308202827-9d24e82272b4
