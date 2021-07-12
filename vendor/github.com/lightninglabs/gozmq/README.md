# gozmq

GoZMQ is a pure Go ZMQ pubsub client implementation.

Only a very limited subset of ZMQ is implemented: NULL security, SUB socket.

## Usage

Please visit https://godoc.org/github.com/tstranex/gozmq for the full
documentation.

## Installation

To install, run:
```
go get github.com/tstranex/gozmq
```

## Example

See example/main.go for a full example.

```go
c, err := gozmq.Subscribe("127.0.0.1:1234", []string{""})
for {
  msg, err := c.Receive()
  // Process message
}
```
