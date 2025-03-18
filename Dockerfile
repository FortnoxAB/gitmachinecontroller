FROM alpine:3.20
WORKDIR /
COPY gmc gmc
USER nobody
ENTRYPOINT ["/gmc"]
