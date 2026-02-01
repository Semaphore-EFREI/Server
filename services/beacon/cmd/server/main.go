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

	beaconv1 "semaphore/beacon/beacon/v1"
	"semaphore/beacon/internal/clients"
	"semaphore/beacon/internal/config"
	"semaphore/beacon/internal/db"
	beacongrpc "semaphore/beacon/internal/grpc"
	internalhttp "semaphore/beacon/internal/http"
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
	clients, err := clients.New(ctx, cfg.AttendanceAddr, cfg.ServiceAuthToken, cfg.GRPCDialTimeout)
	if err != nil {
		log.Fatalf("grpc dial failed: %v", err)
	}
	defer clients.Close()

	server, err := internalhttp.NewServer(cfg, store, clients.Attendance)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serviceAuthInterceptor, err := beacongrpc.NewServiceAuthUnaryInterceptor(cfg.ServiceAuthToken)
	if err != nil {
		log.Fatalf("grpc service auth init failed: %v", err)
	}
	authInterceptor, err := beacongrpc.NewJWTUnaryInterceptor(cfg)
	if err != nil {
		log.Fatalf("grpc jwt auth init failed: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(serviceAuthInterceptor, authInterceptor))
	beaconv1.RegisterBeaconQueryServiceServer(grpcServer, beacongrpc.NewBeaconQueryServer(store))
	beaconv1.RegisterBeaconCommandServiceServer(grpcServer, beacongrpc.NewBeaconCommandServer(store))

	go func() {
		log.Printf("beacon http listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	go func() {
		listener, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			log.Fatalf("grpc listen error: %v", err)
		}
		log.Printf("beacon grpc listening on %s", cfg.GRPCAddr)
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
