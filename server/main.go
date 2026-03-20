package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Szzrain/SealSignMiddleware/middleware"
)

func main() {
	// -------------------------------------------------------------------------
	// 1. Parse flags
	// -------------------------------------------------------------------------
	cfgPath := flag.String("config", "config.yaml", "path to config.yaml")
	flag.Parse()

	// -------------------------------------------------------------------------
	// 2. Load config
	// -------------------------------------------------------------------------
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	log.Printf("loaded %d route rule(s), listening on %s", len(cfg.Routes), cfg.Addr)

	// -------------------------------------------------------------------------
	// 3. Build downstream handler (reverse proxy)
	// -------------------------------------------------------------------------
	proxyHandler, err := NewProxyHandler(cfg.Routes)
	if err != nil {
		log.Fatalf("failed to build proxy handler: %v", err)
	}

	// -------------------------------------------------------------------------
	// 4. Wrap with auth middleware
	// -------------------------------------------------------------------------
	auth := middleware.New(middleware.Config{
		PublicKey: cfg.PublicKey,
		JWTSecret: cfg.JWTSecret,
	})
	defer auth.Stop()

	mux := http.NewServeMux()
	// /token/refresh – validate JWT and conditionally renew; never proxied downstream.
	mux.Handle("/token/refresh", auth.RefreshHandler())
	mux.Handle("/", auth.Handler(proxyHandler))

	// -------------------------------------------------------------------------
	// 5. Start HTTP server with graceful shutdown
	// -------------------------------------------------------------------------
	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Run server in background.
	go func() {
		log.Printf("server starting on %s", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for SIGINT / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down…")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown error: %v", err)
	}
	log.Println("server stopped")
}
