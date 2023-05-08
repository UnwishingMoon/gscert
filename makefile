build:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o bin/gscert-macos-arm64
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/gscert-linux-arm64
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o bin/gscert-windows-arm64.exe


	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/gscert-macos-amd64
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/gscert-linux-amd64
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/gscert-windows-amd64.exe