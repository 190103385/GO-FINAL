FROM golang:latest
ENV APP_HOME /go-final
WORKDIR "$APP_HOME"
COPY . .
RUN go mod download
RUN go build -o go-final
EXPOSE 8080
CMD ["./go-final"]