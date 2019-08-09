# nray

## Overview

Nray is a free, platform and architecture independent port and application layer scanner. 
Apart from regular targets (list of hosts/networks), it supports dynamic target selection, based on source like certificate transparency logs or LDAP. 
Furthermore, nray allow to run in a distributed manner to speed up scans and to perform scans from different vantage points. 
Event-based results allow to further process information during the scan, e.g. using tools like `jq` or full-blown data analysis platforms like elasticsearch or Splunk.

This is the main repo where nray is developed. 
Downloads are [here](https://TODO). 
If you are looking for user documentation, have a look at the [project homepage](https://nray-scanner.org). 
For information related to developing and contributing to nray, continue reading.

Nray is written in pure Go and its versioning follows the [semantic versioning](https://semver.org/) model. 
The development follows [Vincent Driessen's "A successful git branching" model](https://nvie.com/posts/a-successful-git-branching-model/), therefore we try to keep the `master` branch stable and in line with releases whereas development happens on the `development` branch as well as branches derived from there.

## Building 

Care was taken to mostly stay in line with Go's build system, meaning that the project can be built with a plain `go build`. 
Nray is written in pure Go and care was taken to select only dependencies that also fulfill this requirement, therefore a standard Go installation (plus git) is enough to build nray on and for any supported platform.

### With makefile

Nevertheless, there is a makefile that is supposed to be used for building production versions (`make release`) - it ensures that no C dependencies are linked in and symbols are stripped from binaries to save space. 
Also, binaries for most common operating systems are created automatically. 
A call to `make` will build a local development version, tailored to your current OS and architecture with C libraries and Go's race detector linked in.

### Without makefile

Simply run `go build` - in case cross compiling is desired, `GOOS` and `GOARCH` parameters control target OS and architecture.
For nodes, it is possible to inject server location and port directly into the binary: `go build -ldflags "-X main.server=10.0.0.1 -X main.port=8601"`.
To get smaller binaries, strip stuff that is not neccessary away via `-ldflags="-s -w"` when calling `go build`.
If you need to rebuild the protobuf schemas (this is not required unless you change the wire protocol!), run `make create-schemas` (which requires the protobuf compiler on your system). 

## Contributing and Development

Just grab the code and fix stuff that annoys you or hack in new awesome features!
Every contribution is welcome and the goal is to make nray an awesome project for users and contributors!

Your code should check standard checks performend by go vet and go lint. 
I recommend using Visual Studio Code with its Go support enabled, its a really good IDE that brings such issues up early.

### Creating issues

Before opening issues, please check

- Did you read the documentation?
- Are there already similar issues?
- Provide as much environment information as possible: Architecture, operating system, Go version, configuration used etc.
- Try to give steps on how to reproduce the error
- **Please use proper formatting, especially for logs (code tags)**. This greatly increases readability and the chance that somebody looks after your issue.

## License

GPLv3. See LICENSE.
