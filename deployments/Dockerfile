FROM golang:1.12.5-stretch AS builder

RUN echo "deb http://mirrors.163.com/debian stretch main non-free contrib" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install ca-certificates
RUN apt-get install make
RUN apt-get install git
RUN apt-get install gcc libc-dev
RUN apt-get clean

ENV GOPATH=/opt/gopath
ENV PROJECT_PATH=${GOPATH}/src/github.com/deepin-cve/tracker
ENV GO111MODULE=on

ADD . ${PROJECT_PATH}
WORKDIR ${PROJECT_PATH}
RUN make build

FROM golang:1.12.5-stretch

RUN echo "deb http://mirrors.163.com/debian stretch main non-free contrib" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install ca-certificates
RUN apt-get clean

ENV GOPATH=/opt/gopath
ENV PROJECT_PATH=${GOPATH}/src/github.com/deepin-cve/tracker

WORKDIR ${PROJECT_PATH}

COPY --from=builder ${PROJECT_PATH}/deepin_cve_tracker deepin_cve_tracker
COPY --from=builder ${PROJECT_PATH}/configs configs
RUN mkdir data
RUN mkdir /etc/deepin-cve-tracker
COPY configs/config.example.yaml /etc/deepin-cve-tracker/config.yaml

CMD ["./deepin_cve_tracker"]
