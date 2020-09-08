package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"os/signal"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	addr, port string
	agent      string
	banner     string
)

func init() {
	flag.StringVar(&port, "port", "22", "port to bind")
	flag.StringVar(&addr, "addr", "[::]", "addr to bind")
	flag.StringVar(&agent, "agent", "OpenSSH_7.9p1 Debian-10+deb10u2", "server version string to present")
	flag.StringVar(&banner, "banner", "", "server banner message to present")
	flag.Parse()
}

func NewPasswordAuth(logger *(*zap.SugaredLogger)) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(cm ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		(*logger).Infow("password authentication attempt",
			"session", base64.StdEncoding.EncodeToString(cm.SessionID()),
			"user", cm.User(),
			"auth", map[string]string{
				"password": string(password),
				"method":   "password",
			},
			"agent", map[string]string{
				"client": string(cm.ClientVersion()),
				"server": string(cm.ServerVersion()),
			},
			"addr", map[string]string{
				"remote": cm.RemoteAddr().String(),
				"local":  cm.LocalAddr().String(),
			},
		)
		return nil, nil
	}
}

func NewAuthLogCallback(logger *(*zap.SugaredLogger)) func(ssh.ConnMetadata, string, error) {
	return func(cm ssh.ConnMetadata, method string, err error) {
		message := "authentication succeeded"
		if err != nil {
			message = "connection received"
		}

		(*logger).Infow(message,
			"session", base64.StdEncoding.EncodeToString(cm.SessionID()),
			"user", cm.User(),
			// TODO log method
			"agent", map[string]string{
				"client": string(cm.ClientVersion()),
				"server": string(cm.ServerVersion()),
			},
			"addr", map[string]string{
				"remote": cm.RemoteAddr().String(),
				"local":  cm.LocalAddr().String(),
			},
		)
	}
}

func LogRequests(logger *zap.SugaredLogger, context string, reqs <-chan *ssh.Request, runshell chan<- bool) {
	defer func() {
		if runshell != nil {
			close(runshell)
		}
	}()
	for req := range reqs {
		if runshell != nil {
			// RFC 4254 6.5
			switch req.Type {
			case "shell":
				runshell <- true
				close(runshell)
				runshell = nil
			case "exec":
				fallthrough
			case "subsystem":
				runshell <- false
				close(runshell)
				runshell = nil
			}
		}

		var payload interface{}
		if len(req.Payload) != 0 {
			payload = base64.StdEncoding.EncodeToString(req.Payload)
		}

		logger.Infow("request received",
			"request", map[string]interface{}{
				"context":   context,
				"type":      req.Type,
				"wantreply": req.WantReply,
				"payload":   payload,
			})

		if req.WantReply {
			// accept any request, so that the
			// client sends us more infos
			req.Reply(true, nil)
		}
	}
}

func handleChannels(logger *zap.SugaredLogger, chreqs <-chan ssh.NewChannel) {
	for chreq := range chreqs {
		var payload interface{}
		if pl := chreq.ExtraData(); len(pl) != 0 {
			payload = base64.StdEncoding.EncodeToString(pl)
		}

		logger.Infow("channel requested",
			"channel", map[string]interface{}{
				"type":    chreq.ChannelType(),
				"payload": payload,
			})

		if t := chreq.ChannelType(); t != "session" {
			logger.Infow("unknown channel type", "type", t)
			chreq.Reject(ssh.UnknownChannelType, "")
			continue
		}

		ch, reqs, err := chreq.Accept()
		if err != nil {
			logger.Infow("error while accepting channel request",
				"error", err)
			continue
		}
		defer ch.Close()

		runshell := make(chan bool)
		go LogRequests(logger, "channel", reqs, runshell)

		select {
		case <-time.After(10 * time.Second):
			// time out if client doesn't request shell/exec/subsystem
			return
		case shellp, ok := <-runshell:
			if !ok || !shellp {
				// client asked for something that's not a shell
				return
			}
		}

		go func() {
			term := terminal.NewTerminal(ch, "sh-4.3$ ")
			for {
				// also log incomplete lines
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				logger.Infow("received interactive command", "line", line)
			}
			ch.Close()
		}()
	}
}

func handler(logger *zap.SugaredLogger, ctx context.Context, conn *ssh.ServerConn, chreqs <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	logger.Infow("ssh connection opened")
	defer logger.Infow("ssh connection closed")

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		LogRequests(logger, "session", reqs, nil)
		wg.Done()
	}()
	go func() {
		handleChannels(logger.With("context", "channel"), chreqs)
		wg.Done()
	}()

	wg.Wait()
	conn.Close()
	conn.Conn.Close()
}

func main() {

	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel
	})
	jsonenc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewTee(
		zapcore.NewCore(jsonenc, zapcore.Lock(os.Stderr), highPriority),
		zapcore.NewCore(jsonenc, zapcore.Lock(os.Stdout), lowPriority),
	)
	logger := zap.New(core).Sugar()
	defer logger.Sync()

	config := ssh.ServerConfig{
		NoClientAuth:     true,
		ServerVersion:    "SSH-2.0-" + agent,
		PasswordCallback: NewPasswordAuth(&logger),
		AuthLogCallback:  NewAuthLogCallback(&logger),
	}

	if banner != "" {
		config.BannerCallback = func(_ ssh.ConnMetadata) string {
			return banner
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// regurlarly refresh host key
		t := time.NewTimer(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				t.Reset(5 * time.Minute)

				_, privEd25519, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					logger.Fatalw("could not generate ed25519 host key",
						"error", err)
				}

				privRSA, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					logger.Fatalw("could not generate rsa host key",
						"error", err)
				}

				fingerprints := map[string]string{}
				for _, priv := range []interface{}{privEd25519, privRSA} {
					signer, err := ssh.NewSignerFromKey(priv)
					if err != nil {
						logger.Fatalw("could not generate signer from key",
							"error", err)
					}
					fingerprints[signer.PublicKey().Type()] = ssh.FingerprintSHA256(signer.PublicKey())
					config.AddHostKey(signer)
				}
				logger.Infow("rotated hostkey", "hostkey", fingerprints)

			}
		}
	}()

	socket, err := net.Listen("tcp", fmt.Sprintf("%s:%s", addr, port))
	if err != nil {
		logger.Fatalw("could not bind socket", "error", err)
	}
	defer socket.Close()

	done := make(chan struct{})

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sigchan

		cancel()
		close(done)
		if err := socket.Close(); err != nil {
			logger.Fatalw("could not clase socket", "error", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := socket.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}

			logger.Infow("error during accept", "error", err)
			continue
		}

		logger := logger.With(
			"addr", map[string]string{
				"remote": conn.RemoteAddr().String(),
				"local":  conn.LocalAddr().String(),
			},
		)

		scon, chans, reqs, err := ssh.NewServerConn(conn, &config)
		if err != nil {
			logger.Infow("opening ssh connection failed",
				"error", err,
			)
			conn.Close()
			continue
		}

		go handler(logger.With(
			"session", base64.StdEncoding.EncodeToString(scon.SessionID()),
			"user", scon.User(),
			"agent", map[string]string{
				"client": string(scon.ClientVersion()),
				"server": string(scon.ServerVersion()),
			},
		), ctx, scon, chans, reqs)
	}
}
