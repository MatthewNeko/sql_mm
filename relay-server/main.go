package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the relay config file")
	listen := flag.String("listen", "", "override the listen address from the config file")
	showVersion := flag.Bool("version", false, "print the relay version and exit")
	genKey := flag.Bool("genkey", false, "print a fresh 32-byte pre-shared key as hex and exit")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	if *genKey {
		buf := make([]byte, relayKeyBytes)
		if _, err := rand.Read(buf); err != nil {
			logger.Fatalf("entropy: %v", err)
		}
		fmt.Println(hex.EncodeToString(buf))
		return
	}

	if *showVersion {
		logger.Printf("sqlmm-relay %s (protocol %d)", relayVersion, protocolVersion)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		// In-flight sessions die with the process. The plugin treats a dropped
		// socket as a lost connection and re-establishes it on the next
		// operation, so exiting immediately is safe; it is just abrupt.
		logger.Printf("shutting down")
		os.Exit(0)
	}()

	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
