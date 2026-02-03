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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	academicsv1 "semaphore/academics/academics/v1"
	attendancev1 "semaphore/attendance/attendance/v1"
	identityv1 "semaphore/auth-identity/identity/v1"
	"semaphore/auth-identity/internal/config"
	"semaphore/auth-identity/internal/db"
	identitygrpc "semaphore/auth-identity/internal/grpc"
	internalhttp "semaphore/auth-identity/internal/http"
	"semaphore/auth-identity/internal/repository"
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

	store := repository.NewStore(pool)

	if cfg.ServiceAuthToken == "" {
		log.Fatal("service auth token required")
	}

	grpcCtx, cancel := context.WithTimeout(ctx, cfg.GRPCDialTimeout)
	academicsConn, err := grpc.DialContext(
		grpcCtx,
		cfg.AcademicsGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(serviceAuthUnaryClientInterceptor(cfg.ServiceAuthToken)),
	)
	cancel()
	if err != nil {
		log.Fatalf("grpc dial failed: %v", err)
	}
	defer func() {
		if err := academicsConn.Close(); err != nil {
			log.Printf("academics grpc close error: %v", err)
		}
	}()

	grpcCtx, cancel = context.WithTimeout(ctx, cfg.GRPCDialTimeout)
	attendanceConn, err := grpc.DialContext(
		grpcCtx,
		cfg.AttendanceGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(serviceAuthUnaryClientInterceptor(cfg.ServiceAuthToken)),
	)
	cancel()
	if err != nil {
		log.Fatalf("attendance grpc dial failed: %v", err)
	}
	defer func() {
		if err := attendanceConn.Close(); err != nil {
			log.Printf("attendance grpc close error: %v", err)
		}
	}()

	server, err := internalhttp.NewServer(
		cfg,
		store,
		academicsv1.NewAcademicsQueryServiceClient(academicsConn),
		academicsv1.NewAcademicsCommandServiceClient(academicsConn),
		attendancev1.NewAttendanceCommandServiceClient(attendanceConn),
	)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}
	serviceAuthInterceptor, err := identitygrpc.NewServiceAuthUnaryInterceptor(cfg.ServiceAuthToken)
	if err != nil {
		log.Fatalf("grpc service auth init failed: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(serviceAuthInterceptor))
	identityv1.RegisterIdentityQueryServiceServer(grpcServer, identitygrpc.NewIdentityServer(store))

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("auth-identity listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	go func() {
		listener, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			log.Fatalf("grpc listen error: %v", err)
		}
		log.Printf("auth-identity gRPC listening on %s", cfg.GRPCAddr)
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

const serviceTokenHeader = "x-service-token"

func serviceAuthUnaryClientInterceptor(serviceToken string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, serviceTokenHeader, serviceToken)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
