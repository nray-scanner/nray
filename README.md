# nray

## Overview

Nray is a free, platform and architecture independent port and application layer scanner. 
nray runs in a distributed manner to speed up scans and to perform scans from different vantage points. 
Event-based results allow to further process information during the scan, e.g. using tools like `jq`.

If you are looking for user documentation, have a look at the [project homepage](https://nray-scanner.org). 
For information related to developing and contributing to nray, continue reading.

## Building 

You can build the project after a git checkout by calling `go build`. 
Nray is written in pure Go and care was taken to select only dependencies that also fulfill this requirement, therefore a standard Go installation (plus git) is enough to build nray on and for any supported platform - this means that there is also **no** dependency on libraries like `libpcap`.

### With makefile

Nevertheless, there is a makefile that is supposed to be used for building production versions (`make release`) - it ensures that no C dependencies are linked in and symbols are stripped from binaries to save space. 
Also, binaries for most common operating systems are created automatically. 
A call to `make` will build a local development version, tailored to your current OS and architecture with C libraries and Go's race detector linked in.

### Without makefile

Simply run `go build` - in case cross compiling is desired, `GOOS` and `GOARCH` parameters control target OS and architecture.
For nodes, it is possible to inject server location and port directly into the binary: `go build -ldflags "-X main.server=10.0.0.1 -X main.port=8601"`.
To get smaller binaries, strip stuff that is not necessary away via `-ldflags="-s -w"` when calling `go build`.
If you need to rebuild the protobuf schemas (this is not required unless you change the wire protocol!), run `make create-schemas` (which requires the protobuf compiler on your system). 

## Contributing and Development

Just grab the code and fix stuff that annoys you or hack in new awesome features!
Every contribution is welcome and the goal is to make nray an awesome project for users and contributors!

Your code should pass standard checks performed by go vet and go lint. 
Nray is always developed against the latest Go release, so if you are having trouble building nray, check if you have the latest go version installed.

## Legal stuff

Copyright 2019 by Michael Eder. 
Licensed under GPLv3. See LICENSE.
