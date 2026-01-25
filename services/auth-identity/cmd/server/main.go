package main

import (
  "context"
  "log"
  "net/http"
  "os"
  "os/signal"
  "syscall"
  "time"

  "semaphore/auth-identity/internal/config"
  "semaphore/auth-identity/internal/db"
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
  server := internalhttp.NewServer(cfg, store)

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

  <-ctx.Done()

  shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()

  if err := httpServer.Shutdown(shutdownCtx); err != nil {
    log.Printf("shutdown error: %v", err)
  }
}
