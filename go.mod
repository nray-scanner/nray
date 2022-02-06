module github.com/nray-scanner/nray

go 1.14

require (
	bitbucket.org/creachadair/shell v0.0.7 // indirect
	github.com/Microsoft/go-winio v0.4.15 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/bitfield/script v0.18.3
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/golang/time v0.0.0-20211116232009-f0f3c7e86c11
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/shirou/gopsutil v3.20.10+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.8.1 // indirect
	github.com/spf13/cobra v1.3.0
	github.com/spf13/viper v1.10.1
	github.com/zmap/go-iptree v0.0.0-20210731043055-d4e632617837
	golang.org/x/sys v0.0.0-20220204135822-1c1b9b1eba6a // indirect
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	nanomsg.org/go/mangos/v2 v2.0.8
)

replace github.com/golang/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4

replace golang.org/x/time => github.com/golang/time v0.0.0-20190308202827-9d24e82272b4
