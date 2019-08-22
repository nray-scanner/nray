TARGET_NAME=nray

all: prepare build-localarch

clean:
	rm -rf ./build/

build-jobs: build-x86-linux build-x64-linux build-armv7-linux build-x64-windows build-x86-windows build-darwin

create-schemas: 
	protoc --go_out=. ./schemas/*.proto

prepare:
	mkdir -p ./build
	cp nray-conf.yaml ./build/

build-localarch:
	go build -race -ldflags "-X main.server=127.0.0.1 -X main.port=8601" -o build/$(TARGET_NAME)_localhardcoded ./nray.go 
	go build -race -o build/$(TARGET_NAME) ./nray.go 

build-x86-linux: 
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-x86-linux ./nray.go 

build-x64-linux: 
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-x64-linux ./nray.go 

# raspberry pi
build-armv7-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-armv7-linux ./nray.go 

build-x64-windows: 
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-x64-windows.exe ./nray.go 

build-x86-windows: 
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-x86-windows.exe ./nray.go 

build-darwin: 
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -o build/$(TARGET_NAME)-macos ./nray.go 

calculate-hashes:
	sha256sum build/* > build/checksums.txt

create-archive:
	zip -r release.zip build/

release: clean prepare build-jobs calculate-hashes create-archive

.PHONY: docker
docker:	build-x64-linux
	docker build -t nrayscanner/nray-debian:1.0.1 -t nrayscanner/nray-debian:latest -f docker/dockerfile-debian .
	docker build -t nrayscanner/nray-scratch:1.0.1 -t nrayscanner/nray-scratch:latest -f docker/dockerfile-scratch  .
