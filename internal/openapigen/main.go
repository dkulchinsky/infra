package main

import (
	"fmt"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/infrahq/infra/internal"
	"github.com/infrahq/infra/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing command line argument: path to openapi spec file")
	}
	filename := args[0]

	s := server.Server{}
	routes := s.GenerateRoutes(prometheus.NewRegistry())

	return server.WriteOpenAPIDocToFile(routes.OpenAPIDocument, internal.FullVersion(), filename)
}
