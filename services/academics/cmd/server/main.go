package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/academics/internal/clients"
	"semaphore/academics/internal/config"
	"semaphore/academics/internal/db"
	academicsgrpc "semaphore/academics/internal/grpc"
	internalhttp "semaphore/academics/internal/http"
)

func main() {
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db connection failed: %v", err)
	}
	defer pool.Close()

	store := db.NewStore(pool)
	clients, err := clients.New(ctx, cfg.AttendanceGRPCAddr, cfg.BeaconGRPCAddr, cfg.GRPCDialTimeout)
	if err != nil {
		log.Fatalf("grpc dial failed: %v", err)
	}
	defer clients.Close()

	server, err := internalhttp.NewServer(cfg, store, clients.Attendance, clients.Beacon)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}

	grpcServer := grpc.NewServer()
	academicsv1.RegisterAcademicsQueryServiceServer(grpcServer, academicsgrpc.NewAcademicsServer(store.Queries))

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("academics http listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	go func() {
		listener, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			log.Fatalf("grpc listen error: %v", err)
		}
		log.Printf("academics grpc listening on %s", cfg.GRPCAddr)
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("grpc server error: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	grpcServer.GracefulStop()
}
