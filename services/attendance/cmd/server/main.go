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

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/attendance/internal/clients"
	"semaphore/attendance/internal/config"
	"semaphore/attendance/internal/db"
	attendancegrpc "semaphore/attendance/internal/grpc"
	internalhttp "semaphore/attendance/internal/http"
	"semaphore/attendance/internal/jobs"
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
	clients, err := clients.New(ctx, cfg.AcademicsGRPCAddr, cfg.IdentityGRPCAddr, cfg.BeaconGRPCAddr, cfg.ServiceAuthToken, cfg.GRPCDialTimeout)
	if err != nil {
		log.Fatalf("grpc dial failed: %v", err)
	}
	defer clients.Close()

	var redisClient *redis.Client
	if cfg.RedisAddr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
		})
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := redisClient.Ping(pingCtx).Err(); err != nil {
			cancel()
			log.Fatalf("redis ping failed: %v", err)
		}
		cancel()
		defer func() {
			if err := redisClient.Close(); err != nil {
				log.Printf("redis close error: %v", err)
			}
		}()
	}

	server, err := internalhttp.NewServer(cfg, store, clients.Academics, clients.Identity, clients.Beacon, redisClient)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serviceAuthInterceptor, err := attendancegrpc.NewServiceAuthUnaryInterceptor(cfg.ServiceAuthToken)
	if err != nil {
		log.Fatalf("grpc service auth init failed: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(serviceAuthInterceptor))
	attendancev1.RegisterAttendanceCommandServiceServer(grpcServer, attendancegrpc.NewAttendanceServer(store, clients.Academics))
	attendancev1.RegisterAttendanceQueryServiceServer(grpcServer, attendancegrpc.NewAttendanceQueryServer(store))
	jobs.StartSignatureCloseJob(ctx, cfg, clients.AcademicsCommand)

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
