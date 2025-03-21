FROM alpine:3.21
RUN apk add --no-cache tzdata ca-certificates curl
WORKDIR /
COPY gmc gmc
USER nobody
ENTRYPOINT ["/gmc"]
