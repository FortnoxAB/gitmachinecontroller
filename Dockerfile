FROM alpine:3.21
RUN apk add --no-cache tzdata ca-certificates curl
WORKDIR /
COPY gmc gmc
COPY --chmod=444 binary-checksum /binary-checksum
USER nobody
ENTRYPOINT ["/gmc"]
