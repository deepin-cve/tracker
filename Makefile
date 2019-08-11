PROG=deepin_cve_tracker

build:
	go build -o ${PROG} cmd/main.go

clean:
	rm -f ${PROG}

rebuild: clean build
