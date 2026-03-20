package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Szzrain/SealSignMiddleware/procs"
)

var flagPrivKey = flag.String("privkey", "keys/private.hex", "path to 64-byte Ed25519 private key hex file")

// dirOf returns the directory component of path, always ending with "/".
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i+1]
		}
	}
	return "./"
}

func loadOrGeneratePrivKey(hexFile string) ed25519.PrivateKey {
	raw, err := os.ReadFile(hexFile)
	if err == nil {
		decoded, err2 := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err2 != nil {
			log.Fatalf("decode private key: %v", err2)
		}
		if len(decoded) != ed25519.PrivateKeySize {
			log.Fatalf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(decoded))
		}
		log.Printf("loaded private key from %s", hexFile)
		return decoded
	}

	// File not found – generate a fresh pair.
	log.Printf("key file %s not found, generating new Ed25519 key pair…", hexFile)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}

	dir := dirOf(hexFile)
	privPath := hexFile
	pubPath := dir + "public.hex"

	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		log.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		log.Fatalf("write public key: %v", err)
	}

	log.Printf("private key written to %s", privPath)
	log.Printf("public  key written to %s", pubPath)
	log.Printf("──────────────────────────────────────────────────────────────")
	log.Printf("  PASTE this into server/config.yaml → auth.public_key_hex_file:")
	log.Printf("  %s", hex.EncodeToString(pub))
	log.Printf("  (or point public_key_hex_file to %s)", pubPath)
	log.Printf("──────────────────────────────────────────────────────────────")

	return priv
}

func BuildSignature(privKey ed25519.PrivateKey, uin uint64) string {
	var msg [16]byte
	binary.BigEndian.PutUint64(msg[0:8], uin)
	binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().Unix()))

	sig := ed25519.Sign(privKey, msg[:])

	var payload [80]byte
	copy(payload[0:16], msg[:])
	copy(payload[16:80], sig)

	return base64.StdEncoding.EncodeToString(payload[:])
}

func main() {
	uin := 1471813733
	privKey := loadOrGeneratePrivKey(*flagPrivKey)
	milkyExePath, _ := filepath.Abs(filepath.Join("C:\\Users\\MSI-NB\\RiderProjects\\LagrangeV2\\Lagrange.Milky\\bin\\Debug\\net10.0", "Lagrange.Milky"))
	milkyExePath = filepath.ToSlash(milkyExePath) // windows平台需要这个替换
	if runtime.GOOS == "windows" {
		milkyExePath += ".exe" //nolint:ineffassign
	}
	command := fmt.Sprintf(`"%s"`, milkyExePath)
	p := procs.NewProcess(command)
	p.Dir = "C:\\Users\\MSI-NB\\RiderProjects\\LagrangeV2\\Lagrange.Milky\\bin\\Debug\\net10.0"
	p.Env = []string{
		fmt.Sprintf("APP_LAUNCHER_SIG=%s", BuildSignature(privKey, uint64(uin))),
	}

	p.OutputHandler = func(line string, _type string) string {
		fmt.Printf("Milky 输出 [%s]: %s\n", _type, strings.TrimSpace(line))
		return ""
	}

	run := func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("MilkyInteral 异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()

		// processStartTime := time.Now().Unix()
		errRun := p.Start()

		if errRun == nil {
			errRun = p.Wait() //nolint:ineffassign
		}

		if errRun != nil {
			fmt.Print("Milky 进程异常退出: ", errRun)
			// Maybe some state change here
		} else {
			fmt.Print("Milky 进程退出")
		}
	}

	go run()
	// 1. 创建一个用于接收信号的通道
	// 必须使用缓冲通道，否则可能会错过信号
	sigChan := make(chan os.Signal, 1)

	// 2. 注册要监听的信号
	// os.Interrupt 对应 Ctrl+C
	// syscall.SIGTERM 对应常见的结束进程请求（如 Kubernetes 停止容器）
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Println("程序已启动，等待 Ctrl+C 信号...")

	// 3. 阻塞读取通道
	// 程序运行到这里会停住，直到 sigChan 收到信号
	sig := <-sigChan

	fmt.Printf("\n接收到信号: %v。正在安全退出...\n", sig)

	// 这里可以放置你的收尾工作（如关闭数据库连接、保存文件等）
	_ = p.Stop()
	_ = p.Wait()
	fmt.Println("程序已停止。")
}
