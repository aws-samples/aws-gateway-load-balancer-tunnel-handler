FROM amazonlinux:2023.6.20250203.1

RUN yum update; yum install -y iproute-tc iptables tcpdump iputils procps

COPY example-scripts/* .
COPY gwlbtun .

ENTRYPOINT ["./gwlbtun"] 
CMD ["-c", "./create-route.sh", "-p", "80"]
