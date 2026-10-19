package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/northbridge-ops/jito_exporter/pb/auth"
	"github.com/northbridge-ops/jito_exporter/pb/bundle"
	"github.com/northbridge-ops/jito_exporter/pb/packet"
	"github.com/northbridge-ops/jito_exporter/pb/searcher"
)

const (
	tipFloorURL    = "https://bundles.jito.wtf/api/v1/bundles/tip_floor"
	lamportsPerSOL = 1e9
)

var (
	tipFloor = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jito_tip_floor_lamports",
		Help: "Jito landed tip floor by percentile, in lamports.",
	}, []string{"percentile"})
	sent     = prometheus.NewCounter(prometheus.CounterOpts{Name: "canary_sent_total", Help: "Canary bundles accepted by the block engine."})
	landed   = prometheus.NewCounter(prometheus.CounterOpts{Name: "canary_landed_total", Help: "Canary bundles reported processed on chain."})
	dropped  = prometheus.NewCounter(prometheus.CounterOpts{Name: "canary_dropped_total", Help: "Canary bundles rejected or dropped."})
	landRate = prometheus.NewGauge(prometheus.GaugeOpts{Name: "canary_land_rate", Help: "landed / sent since start."})

	sentN atomic.Int64

	httpClient = &http.Client{Timeout: 10 * time.Second}
)

type session struct {
	mu              sync.Mutex
	access, refresh string
	expires         time.Time
	pub             solana.PublicKey
	priv            solana.PrivateKey
	client          auth.AuthServiceClient
}

func (s *session) store(access, refresh *auth.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access, s.expires = access.GetValue(), access.GetExpiresAtUtc().AsTime()
	if refresh != nil {
		s.refresh = refresh.GetValue()
	}
}

func (s *session) login(ctx context.Context) error {
	ch, err := s.client.GenerateAuthChallenge(ctx, &auth.GenerateAuthChallengeRequest{
		Role:   auth.Role_SEARCHER,
		Pubkey: s.pub.Bytes(),
	})
	if err != nil {
		return err
	}
	msg := s.pub.String() + "-" + ch.GetChallenge()
	tokens, err := s.client.GenerateAuthTokens(ctx, &auth.GenerateAuthTokensRequest{
		Challenge:       msg,
		ClientPubkey:    s.pub.Bytes(),
		SignedChallenge: ed25519.Sign(ed25519.PrivateKey(s.priv), []byte(msg)),
	})
	if err == nil {
		s.store(tokens.GetAccessToken(), tokens.GetRefreshToken())
	}
	return err
}

func (s *session) keepFresh(ctx context.Context) {
	for {
		s.mu.Lock()
		wait, refresh := time.Until(s.expires)-time.Minute, s.refresh
		s.mu.Unlock()
		time.Sleep(max(wait, time.Second))
		resp, err := s.client.RefreshAccessToken(ctx, &auth.RefreshAccessTokenRequest{RefreshToken: refresh})
		if err == nil {
			s.store(resp.GetAccessToken(), nil)
		} else if err = s.login(ctx); err != nil {
			log.Printf("token renewal failed: %v", err)
		}
	}
}

func (s *session) withToken(ctx context.Context) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.access == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.access)
}

func (s *session) unary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(s.withToken(ctx), method, req, reply, cc, opts...)
}

func (s *session) stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(s.withToken(ctx), desc, cc, method, opts...)
}

func submit(ctx context.Context, sc searcher.SearcherServiceClient, rpcClient *rpc.Client, payer solana.PrivateKey, tip uint64) error {
	accounts, err := sc.GetTipAccounts(ctx, &searcher.GetTipAccountsRequest{})
	list := accounts.GetAccounts()
	if err != nil || len(list) == 0 {
		return fmt.Errorf("tip accounts: %v", err)
	}
	tipTo := solana.MustPublicKeyFromBase58(list[time.Now().UnixNano()%int64(len(list))])
	bh, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return err
	}
	ix := system.NewTransferInstruction(tip, payer.PublicKey(), tipTo).Build()
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, bh.Value.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		return err
	}
	if _, err := tx.Sign(func(solana.PublicKey) *solana.PrivateKey { return &payer }); err != nil {
		return err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	pkt := &packet.Packet{Data: raw, Meta: &packet.Meta{Size: uint64(len(raw))}}
	_, err = sc.SendBundle(ctx, &searcher.SendBundleRequest{Bundle: &bundle.Bundle{Packets: []*packet.Packet{pkt}}})
	if err == nil {
		sent.Inc()
		sentN.Add(1)
	}
	return err
}

func trackResults(ctx context.Context, sc searcher.SearcherServiceClient) {
	var nLanded float64
	seen := map[string]struct{}{}
	for {
		stream, err := sc.SubscribeBundleResults(ctx, &searcher.SubscribeBundleResultsRequest{})
		for err == nil {
			var res *bundle.BundleResult
			if res, err = stream.Recv(); err != nil {
				break
			}
			switch res.GetResult().(type) {
			case *bundle.BundleResult_Processed, *bundle.BundleResult_Finalized:
				if _, dup := seen[res.GetBundleId()]; dup {
					continue
				}
				seen[res.GetBundleId()] = struct{}{}
				nLanded++
				landed.Inc()
			case *bundle.BundleResult_Dropped, *bundle.BundleResult_Rejected:
				dropped.Inc()
			default:
				continue
			}
			landRate.Set(nLanded / float64(max(sentN.Load(), 1)))
		}
		log.Printf("results feed gone: %v", err)
		time.Sleep(3 * time.Second)
	}
}

func updateTipFloor() error {
	resp, err := httpClient.Get(tipFloorURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var entries []map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil || len(entries) == 0 {
		return fmt.Errorf("tip_floor: status %d: %v", resp.StatusCode, err)
	}
	for _, p := range []string{"25", "50", "75", "95"} {
		tipFloor.WithLabelValues("p" + p).Set(entries[0]["landed_tips_"+p+"th_percentile"] * lamportsPerSOL)
	}
	return nil
}

func main() {
	listen := flag.String("listen", ":9101", "address for /metrics")
	interval := flag.Duration("interval", 30*time.Second, "canary submit interval")
	engine := flag.String("engine", "mainnet.block-engine.jito.wtf:443", "block engine gRPC address")
	rpcURL := flag.String("rpc", rpc.MainNetBeta_RPC, "solana JSON RPC endpoint")
	keyFile := flag.String("keypair", "", "path to solana keygen json file")
	tip := flag.Uint64("tip", 1000, "canary tip in lamports")
	flag.Parse()
	prometheus.MustRegister(tipFloor, sent, landed, dropped, landRate)

	key, err := solana.PrivateKeyFromSolanaKeygenFile(*keyFile)
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	sess := &session{pub: key.PublicKey(), priv: key}
	conn, err := grpc.NewClient(*engine,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithUnaryInterceptor(sess.unary),
		grpc.WithStreamInterceptor(sess.stream),
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	sess.client = auth.NewAuthServiceClient(conn)
	ctx := context.Background()
	if err := sess.login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}
	go sess.keepFresh(ctx)

	sc, rpcClient := searcher.NewSearcherServiceClient(conn), rpc.New(*rpcURL)
	go trackResults(ctx, sc)
	go func() {
		for range time.Tick(*interval) {
			if err := updateTipFloor(); err != nil {
				log.Printf("tip floor update failed: %v", err)
			}
			cctx, cancel := context.WithTimeout(ctx, *interval)
			if err := submit(cctx, sc, rpcClient, key, *tip); err != nil {
				log.Printf("canary failed: %v", err)
			}
			cancel()
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Printf("listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
