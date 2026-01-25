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

	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/attendance/internal/clients"
	"semaphore/attendance/internal/config"
	"semaphore/attendance/internal/db"
	attendancegrpc "semaphore/attendance/internal/grpc"
	internalhttp "semaphore/attendance/internal/http"
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
	clients, err := clients.New(ctx, cfg.AcademicsGRPCAddr, cfg.IdentityGRPCAddr, cfg.GRPCDialTimeout)
	if err != nil {
		log.Fatalf("grpc dial failed: %v", err)
	}
	defer clients.Close()

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           internalhttp.NewServer(cfg, store, clients.Academics, clients.Identity).Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	grpcServer := grpc.NewServer()
	attendancev1.RegisterAttendanceCommandServiceServer(grpcServer, attendancegrpc.NewAttendanceServer(store, clients.Academics))

	go func() {
		log.Printf("attendance http listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	go func() {
		listener, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			log.Fatalf("grpc listen error: %v", err)
		}
		log.Printf("attendance grpc listening on %s", cfg.GRPCAddr)
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
