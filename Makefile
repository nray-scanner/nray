TARGET_NAME=nray

all: prepare build-localarch

clean:
	rm -rf ./build/

build-all: build-linux-amd64 build-linux-arm64 build-linux-armv7 build-windows-amd64 build-windows-arm64 build-darwin-amd64 build-darwin-arm64

prepare:
	mkdir -p ./build
	cp nray-conf.yaml ./build/


build-localarch:
	go build -race -ldflags "-X main.server=127.0.0.1 -X main.port=8601" -o build/$(TARGET_NAME)_localhardcoded ./nray.go 
	go build -race -o build/$(TARGET_NAME) ./nray.go 

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-linux-amd64 ./nray.go

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-linux-arm64 ./nray.go

build-linux-armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-linux-armv7 ./nray.go

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-windows-amd64.exe ./nray.go

build-windows-arm64:
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-windows-arm64.exe ./nray.go

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-darwin-amd64 ./nray.go

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o build/$(TARGET_NAME)-darwin-arm64 ./nray.go

calculate-hashes:
	cd build; sha256sum * > ./checksums.txt; cd ..

create-archive:
	zip -r release.zip build/

release: clean prepare build-all calculate-hashes