FROM golang:1.25

WORKDIR /app

RUN go install github.com/air-verse/air@v1.65.0

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
