package ebpf

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/klog/v2"
)

// bpfFS is the default path for pinned maps
const bpfFS = "/sys/fs/bpf"

// Loader handles loading and managing BPF programs and maps
type Loader struct {
	program   *ebpf.Program
	links     []link.Link
	filterMap *ebpf.Map
	connsMap  *ebpf.Map
	events    *ringbuf.Reader
	podMap    *ebpf.Map
}

// LoaderConfig contains configuration for the BPF loader
type LoaderConfig struct {
	BPFObjPath string
	MapPinPath string
}

// NewLoader creates a new BPF program loader
func NewLoader(cfg LoaderConfig) (*Loader, error) {
	// Ensure pin path exists
	if err := os.MkdirAll(cfg.MapPinPath, 0755); err != nil {
		return nil, fmt.Errorf("creating pin path: %w", err)
	}

	// Load pre-compiled BPF object
	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObjPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF spec: %w", err)
	}

	// Create maps and program
	var objs struct {
		ConntrackProgram     *ebpf.Program `ebpf:"trace_tcp_state"`
		ConntrackRetransProg *ebpf.Program `ebpf:"trace_tcp_retransmit"`
		FilterMap            *ebpf.Map     `ebpf:"filter_map"`
		ConnsMap             *ebpf.Map     `ebpf:"conns"`
		Events               *ebpf.Map     `ebpf:"events"`
		PodMap               *ebpf.Map     `ebpf:"pod_map"`
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: cfg.MapPinPath,
		},
	}); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Create tracepoint links
	tcpStateLink, err := link.Tracepoint("tcp", "tcp_set_state", objs.ConntrackProgram)
	if err != nil {
		return nil, fmt.Errorf("attaching tcp_set_state tracepoint: %w", err)
	}

	tcpRetransLink, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.ConntrackRetransProg)
	if err != nil {
		tcpStateLink.Close()
		return nil, fmt.Errorf("attaching tcp_retransmit_skb tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tcpStateLink.Close()
		tcpRetransLink.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &Loader{
		program:   objs.ConntrackProgram,
		links:     []link.Link{tcpStateLink, tcpRetransLink},
		filterMap: objs.FilterMap,
		connsMap:  objs.ConnsMap,
		events:    reader,
		podMap:    objs.PodMap,
	}, nil
}

// Close cleans up the loader resources
func (l *Loader) Close() error {
	for _, link := range l.links {
		link.Close()
	}
	if l.events != nil {
		l.events.Close()
	}
	if l.program != nil {
		l.program.Close()
	}
	if l.filterMap != nil {
		l.filterMap.Close()
	}
	if l.connsMap != nil {
		l.connsMap.Close()
	}
	if l.podMap != nil {
		l.podMap.Close()
	}
	return nil
}

// ProcessEvents starts processing events from the ring buffer
func (l *Loader) ProcessEvents(ctx context.Context, handler func([]byte)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := l.events.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return nil
				}
				klog.Errorf("Error reading from ring buffer: %v", err)
				continue
			}
			handler(record.RawSample)
		}
	}
}

// GetFilterMap returns the filter map for updating rules
func (l *Loader) GetFilterMap() *ebpf.Map {
	return l.filterMap
}

// GetConnsMap returns the connections map
func (l *Loader) GetConnsMap() *ebpf.Map {
	return l.connsMap
}

// GetPodMap returns the pod mapping
func (l *Loader) GetPodMap() *ebpf.Map {
	return l.podMap
}
