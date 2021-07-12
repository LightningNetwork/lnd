BStream: A Bit Stream helper in Golang 
==================

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/kkdai/bloomfilter/master/LICENSE)  [![GoDoc](https://godoc.org/github.com/kkdai/bstream?status.svg)](https://godoc.org/github.com/kkdai/bstream)  [![Build Status](https://travis-ci.org/kkdai/bstream.svg?branch=master)](https://travis-ci.org/kkdai/bstream)[![](https://goreportcard.com/badge/github.com/kkdai/bstream)
](https://goreportcard.com/report/github.com/kkdai/bstream)



Install
---------------
`go get github.com/kkdai/bstream`


Usage
---------------

```go
	//New a bit stream writer with default 5 byte
	b := NewBStreamWriter(5)
	
	//Write 0xa0a0 into bstream
	b.WriteBits(0xa0a0, 16)
	
	//Read 4 bit out
	result, err := b.ReadBits(4)
	if err != nil {
		log.Printf("result:%x", result)
		//result:a
	}
```

Notes
---------------

- BStream is *not* thread safe. When you need to use it from different goroutines, you need to manage locking yourself.
- You can use the same `*BStream` object for reading & writing. However note that currently it is possible to read zero-value data if you read more bits than what has been written.
- BStream will *not* modify the data provided to `NewBStreamReader`. You can reuse the same `*BStream` object for writing and it will allocate a new underlying buffer.

Inspired
---------------

- [https://github.com/dgryski/go-tsz](https://github.com/dgryski/go-tsz)

Benchmark
---------------
```
BenchmarkWriteBits-4	100000000	        15.3 ns/op
BenchmarkReadBits-4 	50000000	        26.5 ns/op
```

Project52
---------------

It is one of my [project 52](https://github.com/kkdai/project52).


License
---------------

This package is licensed under MIT license. See LICENSE for details.

