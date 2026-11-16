# The issuer. Configure it with the same environment variables as when running
# it directly (see main.go), including BASE_URL, the address users reach it
# at. It keeps its key in /data, so mount a volume there to keep the key when
# the container is replaced:
#
#	docker build -t privacypass .
#	docker run -p 8080:8080 -v privacypass:/data \
#	    -e BASE_URL=https://issuer.example -e OAUTH_CLIENT_ID=... privacypass
FROM golang:1.27
WORKDIR /app
COPY go.mod go.sum *.go privacypass.js wallet.html ./
RUN go build -o privacypass .
VOLUME /data
EXPOSE 8080
CMD ["./privacypass", "-key", "/data/issuer-key.pem"]
