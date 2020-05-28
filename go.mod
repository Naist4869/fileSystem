module fileSystem

go 1.13

require (
	github.com/Naist4869/log v0.0.0-20200521103425-899dfa0728e1
	github.com/corona10/goimagehash v1.0.2
	github.com/davecgh/go-spew v1.1.1
	github.com/go-kratos/kratos v0.4.3-0.20200408075623-52cb7ec27f60
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.5
	github.com/google/wire v0.4.0
	go.uber.org/zap v1.15.0
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e
	google.golang.org/genproto v0.0.0-20200402124713-8ff61da6d932
	google.golang.org/grpc v1.28.1
)

replace github.com/go-kratos/kratos v0.4.3-0.20200408075623-52cb7ec27f60 => ../kratos
