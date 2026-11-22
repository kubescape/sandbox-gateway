// Command mock-anthropic is a stand-in for api.anthropic.com in local runs:
// POST /v1/messages answers with a streamed Messages response, so the stack can
// be exercised without an API key. It speaks plain HTTP; Envoy re-originates
// TLS only toward the real upstream.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	addr := flag.String("listen", ":8080", "listen address")
	delay := flag.Duration("chunk-delay", 20*time.Millisecond, "delay between text deltas")
	words := flag.Int("words", 40, "text deltas per response")
	tlsAddr := flag.String("tls-listen", ":8443", "Q5: a TLS listener with its own self-signed leaf (CN mock-internal), standing in for an in-cluster :443 service")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"bad json"}}`, http.StatusBadRequest)
			return
		}
		log.Info("request", "model", req.Model, "stream", req.Stream, "pid_hint", r.Header.Get("x-sandbox-test-pid"))
		if anthropicScenario(w, req.Model) {
			return
		}
		if !req.Stream {
			w.Header().Set("content-type", "application/json")
			fmt.Fprintf(w, `{"id":"msg_mock","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`, req.Model)
			return
		}
		w.Header().Set("content-type", "text/event-stream")
		w.Header().Set("cache-control", "no-cache")
		fl, _ := w.(http.Flusher)
		send := func(event, data string) {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
			if fl != nil {
				fl.Flush()
			}
		}
		send("message_start", fmt.Sprintf(`{"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":%q,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}`, req.Model))
		send("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		for i := 0; i < *words; i++ {
			select {
			case <-r.Context().Done():
				log.Info("client went away", "after_words", i)
				return
			case <-time.After(*delay):
			}
			b, _ := json.Marshal(strings.Repeat("x", 3) + " ")
			send("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}`, b))
			if i%10 == 9 {
				fmt.Fprint(w, ": ping\n\n")
			}
		}
		send("content_block_stop", `{"type":"content_block_stop","index":0}`)
		send("message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":%d}}`, *words))
		send("message_stop", `{"type":"message_stop"}`)
	})
	// S4: OpenAI Chat Completions and Responses scenarios (model name selects one).
	openai := func(serve func(http.ResponseWriter, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			log.Info("openai request", "path", r.URL.Path, "model", req.Model)
			serve(w, req.Model)
		}
	}
	http.HandleFunc("/v1/chat/completions", openai(chatScenario))
	http.HandleFunc("/v1/responses", openai(responsesScenario))

	// S5: a WebSocket echo, to see whether ext_proc gets post-upgrade bytes.
	http.Handle("/v1/ws", websocket.Handler(func(c *websocket.Conn) {
		log.Info("websocket open")
		var msg string
		for websocket.Message.Receive(c, &msg) == nil {
			_ = websocket.Message.Send(c, "echo:"+msg)
		}
	}))
	go serveTLS(*tlsAddr, log)
	log.Info("mock-anthropic listening", "addr", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Error("serve", "error", err)
		os.Exit(1)
	}
}
