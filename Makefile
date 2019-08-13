PROG=deepin_cve_tracker
DOCKER_TARGET=jouyouyun/deepin-cve-tracker
DOCKER_BUILD_TARGET=${DOCKER_TARGET}.builder

build:
	go build -o ${PROG} cmd/main.go

docker:
	docker build -f deployments/Dockerfile --target builder -t ${DOCKER_BUILD_TARGET}:latest .
	docker build -f deployments/Dockerfile -t ${DOCKER_TARGET}:latest .

docker-push:
	docker push ${DOCKER_TARGET}:latest

clean:
	rm -f ${PROG}

rebuild: clean build
