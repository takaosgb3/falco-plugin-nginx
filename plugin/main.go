// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/fsnotify/fsnotify"
	"github.com/takaosgb3/falco-plugin-nginx/pkg/parser"
)

// NginxPluginConfig represents the plugin configuration
type NginxPluginConfig struct {
	LogPaths []string `json:"log_paths" jsonschema:"title=Log Paths,description=List of nginx log file paths to monitor,default=[/var/log/nginx/access.log]"`
}

// NginxPlugin implements the Falco plugin for nginx monitoring
type NginxPlugin struct {
	plugins.BasePlugin
	config NginxPluginConfig
	parser *parser.Parser
}

// NginxInstance represents an instance of the plugin
type NginxInstance struct {
	source.BaseInstance
	logPaths []string
	eventCh  chan *NginxEvent
	files    map[string]*TailFile
	watcher  *fsnotify.Watcher
	parser   *parser.Parser
}

// TailFile represents a file being tailed
type TailFile struct {
	path   string
	file   *os.File
	reader *bufio.Reader
}

// NginxEvent represents a parsed nginx log event
type NginxEvent struct {
	RemoteAddr  string    `json:"remote_addr"`
	RemoteUser  string    `json:"remote_user"`
	TimeLocal   string    `json:"time_local"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	QueryString string    `json:"query_string"`
	Protocol    string    `json:"protocol"`
	Status      uint64    `json:"status"`
	BytesSent   uint64    `json:"bytes_sent"`
	Referer     string    `json:"referer"`
	UserAgent   string    `json:"user_agent"`
	LogPath     string    `json:"log_path"`
	Raw         string    `json:"raw"`
	Timestamp   time.Time `json:"timestamp"`
}

// Register the plugin
func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &NginxPlugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

// Info returns plugin information
func (n *NginxPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "nginx",
		Description: "Real-time nginx access log monitoring for security threats",
		Contact:     "github.com/takaosgb3/falco-nginx-plugin",
		Version:     "0.3.0",
		EventSource: "nginx",
	}
}

// InitSchema returns the schema for plugin configuration
func (n *NginxPlugin) InitSchema() *sdk.SchemaInfo {
	schema, err := jsonschema.Reflect(&NginxPluginConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init initializes the plugin
func (n *NginxPlugin) Init(config string) error {
	// Set defaults
	n.config = NginxPluginConfig{
		LogPaths: []string{"/var/log/nginx/access.log"},
	}

	// Parse configuration
	if config != "" {
		if err := json.Unmarshal([]byte(config), &n.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Validate
	if len(n.config.LogPaths) == 0 {
		return fmt.Errorf("no log paths configured")
	}

	// Initialize parser with combined format
	parserConfig := parser.Config{
		LogFormat:              "combined",
		SecurityPatterns:       true,
		LargeResponseThreshold: 10 * 1024 * 1024, // 10MB
	}
	n.parser = parser.New(parserConfig)

	return nil
}

// Fields returns the list of extractor fields
func (n *NginxPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "nginx.remote_addr", Display: "Remote Address", Desc: "Client IP address"},
		{Type: "string", Name: "nginx.remote_user", Display: "Remote User", Desc: "Authenticated username"},
		{Type: "string", Name: "nginx.time_local", Display: "Time Local", Desc: "Local time of the request"},
		{Type: "string", Name: "nginx.method", Display: "HTTP Method", Desc: "HTTP request method"},
		{Type: "string", Name: "nginx.path", Display: "Request Path", Desc: "Request URI path"},
		{Type: "string", Name: "nginx.query_string", Display: "Query String", Desc: "Query string parameters"},
		{Type: "string", Name: "nginx.protocol", Display: "Protocol", Desc: "HTTP protocol version"},
		{Type: "uint64", Name: "nginx.status", Display: "Status Code", Desc: "HTTP response status code"},
		{Type: "uint64", Name: "nginx.bytes_sent", Display: "Bytes Sent", Desc: "Response size in bytes"},
		{Type: "string", Name: "nginx.referer", Display: "Referer", Desc: "HTTP referer header"},
		{Type: "string", Name: "nginx.user_agent", Display: "User Agent", Desc: "HTTP user agent"},
		{Type: "string", Name: "nginx.log_path", Display: "Log Path", Desc: "Path to the log file"},
		{Type: "string", Name: "nginx.raw", Display: "Raw Log", Desc: "Raw log line"},
	}
}

// Extract extracts fields from events
func (n *NginxPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var event NginxEvent
	decoder := gob.NewDecoder(evt.Reader())
	if err := decoder.Decode(&event); err != nil {
		return err
	}

	switch req.Field() {
	case "nginx.remote_addr":
		req.SetValue(event.RemoteAddr)
	case "nginx.remote_user":
		req.SetValue(event.RemoteUser)
	case "nginx.time_local":
		req.SetValue(event.TimeLocal)
	case "nginx.method":
		req.SetValue(event.Method)
	case "nginx.path":
		req.SetValue(event.Path)
	case "nginx.query_string":
		req.SetValue(event.QueryString)
	case "nginx.protocol":
		req.SetValue(event.Protocol)
	case "nginx.status":
		req.SetValue(event.Status)
	case "nginx.bytes_sent":
		req.SetValue(event.BytesSent)
	case "nginx.referer":
		req.SetValue(event.Referer)
	case "nginx.user_agent":
		req.SetValue(event.UserAgent)
	case "nginx.log_path":
		req.SetValue(event.LogPath)
	case "nginx.raw":
		req.SetValue(event.Raw)
	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	return nil
}

// Open opens a new instance of the plugin
func (n *NginxPlugin) Open(params string) (source.Instance, error) {
	log.Printf("nginx plugin: Opening instance with log paths: %v", n.config.LogPaths)
	inst := &NginxInstance{
		logPaths: n.config.LogPaths,
		eventCh:  make(chan *NginxEvent, 1000),
		files:    make(map[string]*TailFile),
		parser:   n.parser,
	}

	// Set up file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	inst.watcher = watcher

	// Start watching files
	for _, path := range inst.logPaths {
		if err := inst.startTailing(path); err != nil {
			// Log warning but continue
			fmt.Printf("Warning: failed to start tailing %s: %v\n", path, err)
		}
	}

	// Start watcher goroutine
	go inst.watchFiles()

	return inst, nil
}

// startTailing starts tailing a file
func (n *NginxInstance) startTailing(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Open file (create if doesn't exist)
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", path, err)
	}

	// Get file info to log size
	if stat, err := file.Stat(); err == nil {
		log.Printf("nginx plugin: Opened file %s (size: %d bytes)", path, stat.Size())
	}

	// For initial development/testing, read from beginning
	// In production, you might want to seek to end
	// file.Seek(0, io.SeekEnd)

	tf := &TailFile{
		path:   path,
		file:   file,
		reader: bufio.NewReader(file),
	}
	n.files[path] = tf

	// Add to watcher
	if err := n.watcher.Add(path); err != nil {
		// Log error and return
		log.Printf("Failed to add file to watcher: %v", err)
		return err
	}

	// Start tailing goroutine
	go n.tailFile(tf)

	return nil
}

// tailFile tails a file
func (n *NginxInstance) tailFile(tf *TailFile) {
	for {
		line, err := tf.reader.ReadString('\n')
		if err != nil {
			// Check if we have a partial line
			if len(line) > 0 {
				// Process partial line (might be the last line without newline)
				line = strings.TrimSpace(line)
				if line != "" {
					event := n.parseLine(line, tf.path)
					if event != nil {
						log.Printf("nginx plugin: Sending event for request (partial): %s %s", event.Method, event.Path)
						select {
						case n.eventCh <- event:
						default:
							// Channel full, drop event
							log.Printf("nginx plugin: WARNING - Event channel full, dropping event")
						}
					}
				}
			}
			// Sleep and retry for new data
			time.Sleep(100 * time.Millisecond)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse the line
		event := n.parseLine(line, tf.path)
		if event != nil {
			log.Printf("nginx plugin: Sending event for request: %s %s", event.Method, event.Path)
			select {
			case n.eventCh <- event:
			default:
				// Channel full, drop event
				log.Printf("nginx plugin: WARNING - Event channel full, dropping event")
			}
		}
	}
}

// parseLine parses a nginx log line
func (n *NginxInstance) parseLine(line, path string) *NginxEvent {
	// Use the parser package to parse the line
	entry, err := n.parser.Parse(line)
	if err != nil {
		// Log parsing errors for debugging
		log.Printf("Failed to parse line: %v (line: %s)", err, line)
		return nil
	}

	// Convert LogEntry to NginxEvent
	return &NginxEvent{
		RemoteAddr:  entry.RemoteAddr,
		RemoteUser:  entry.RemoteUser,
		TimeLocal:   entry.TimeLocal.Format("02/Jan/2006:15:04:05 -0700"),
		Method:      entry.Method,
		Path:        entry.Path,
		QueryString: entry.QueryString,
		Protocol:    entry.HTTPVersion,
		Status:      uint64(entry.Status),
		BytesSent:   uint64(entry.BodyBytes),
		Referer:     entry.Referer,
		UserAgent:   entry.UserAgent,
		LogPath:     path,
		Raw:         line,
		Timestamp:   entry.TimeLocal,
	}
}

// watchFiles watches for file changes
func (n *NginxInstance) watchFiles() {
	for {
		select {
		case event, ok := <-n.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				// File was written to, reader will pick up new lines
				log.Printf("File modified: %s", event.Name)
			}
		case err, ok := <-n.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Watcher error: %v\n", err)
		}
	}
}

// Close closes the instance
func (n *NginxInstance) Close() {
	if n.watcher != nil {
		n.watcher.Close()
	}
	for _, tf := range n.files {
		tf.file.Close()
	}
	close(n.eventCh)
}

// NextBatch returns the next batch of events
func (n *NginxInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	count := 0
	timeout := time.After(100 * time.Millisecond)

	for count < evts.Len() {
		select {
		case event, ok := <-n.eventCh:
			if !ok {
				if count == 0 {
					return 0, sdk.ErrEOF
				}
				return count, nil
			}

			// Encode event
			evt := evts.Get(count)
			encoder := gob.NewEncoder(evt.Writer())
			if err := encoder.Encode(event); err != nil {
				continue
			}

			// Set timestamp
			evt.SetTimestamp(uint64(event.Timestamp.UnixNano()))

			count++

		case <-timeout:
			if count == 0 {
				return 0, sdk.ErrTimeout
			}
			return count, nil
		}
	}

	return count, nil
}

// main is required but empty as the plugin is loaded as a library
func main() {}
