// +build wireinject

// The build tag makes sure the stub is not built in the final build.
package service

import (
	"fileSystem/internal/dao"
	"fileSystem/internal/server/grpc"

	"github.com/google/wire"
)

//go:generate kratos tool wire
func newTestService() (*Service, func(), error) {
	panic(wire.Build(dao.Provider, grpc.New, Provider))
}
