# The demo origin. Build it from the repository root, and point it at the
# issuer's public URL with ISSUER_URL (see main.go):
#
#	docker build -t privacypass-origin -f demo/origin/Dockerfile .
#	docker run -p 8081:8081 -e ISSUER_URL=https://issuer.example privacypass-origin
FROM golang:1.27
WORKDIR /app
COPY go.mod go.sum ./
COPY verify verify
COPY demo/origin demo/origin
RUN go build -o origin ./demo/origin
EXPOSE 8081
CMD ["./origin"]
