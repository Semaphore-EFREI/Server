package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"semaphore/beacon/internal/clients"
	"semaphore/beacon/internal/config"
	"semaphore/beacon/internal/db"
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
	clients, err := clients.New(ctx, cfg.AttendanceAddr, cfg.GRPCDialTimeout)
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

	go func() {
		log.Printf("beacon http listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
