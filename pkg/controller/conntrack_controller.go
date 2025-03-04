package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	conntrackv1alpha1 "github.com/vobbilis/codegen/visual/pkg/apis/conntrack/v1alpha1"
	"github.com/vobbilis/codegen/visual/pkg/ebpf"
	"github.com/vobbilis/codegen/visual/pkg/metrics"
)

const (
	// bpfFSPath is the default path for BPF filesystem
	bpfFSPath = "/sys/fs/bpf"
	// bpfObjPath is the path to the compiled BPF object
	bpfObjPath = "bpf/conntrack.bpf.o"
)

// Controller manages the connection tracking configuration
type Controller struct {
	client     cache.SharedIndexInformer
	queue      workqueue.RateLimitingInterface
	loader     *ebpf.Loader
	mapUpdater *ebpf.MapUpdater
	metrics    *metrics.MetricsCollector
}

// NewController creates a new connection tracking controller
func NewController(informer cache.SharedIndexInformer) (*Controller, error) {
	c := &Controller{
		client: informer,
		queue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "conntrack"),
	}

	// Set up event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueConfig,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueConfig(new)
		},
		DeleteFunc: c.enqueueConfig,
	})

	return c, nil
}

// Run starts the controller
func (c *Controller) Run(ctx context.Context) error {
	defer c.queue.ShutDown()

	// Initialize BPF components
	if err := c.initBPF(); err != nil {
		return fmt.Errorf("initializing BPF: %w", err)
	}
	defer c.loader.Close()

	// Start event processing
	go c.processEvents(ctx)

	// Start workers
	for i := 0; i < 2; i++ {
		go wait.Until(c.runWorker, time.Second, ctx.Done())
	}

	<-ctx.Done()
	return nil
}

// initBPF initializes BPF program and maps
func (c *Controller) initBPF() error {
	// Create loader
	loader, err := ebpf.NewLoader(ebpf.LoaderConfig{
		BPFObjPath: bpfObjPath,
		MapPinPath: filepath.Join(bpfFSPath, "conntrack"),
	})
	if err != nil {
		return fmt.Errorf("creating BPF loader: %w", err)
	}
	c.loader = loader

	// Create map updater
	updater, err := ebpf.NewMapUpdater(loader.GetFilterMap())
	if err != nil {
		return fmt.Errorf("creating map updater: %w", err)
	}
	c.mapUpdater = updater

	return nil
}

// processEvents handles events from the BPF program
func (c *Controller) processEvents(ctx context.Context) {
	err := c.loader.ProcessEvents(ctx, func(data []byte) {
		// Parse event
		var event struct {
			Timestamp uint64
			Type      uint32
			Key       conntrackv1alpha1.ConnKey
			Info      conntrackv1alpha1.ConnInfo
		}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			klog.Errorf("Failed to parse event: %v", err)
			return
		}

		// Update metrics based on event type
		switch event.Type {
		case 1: // New connection
			c.metrics.RecordNewConnection("new")
		case 2: // Connection closed
			c.metrics.RecordNewConnection("closed")
		case 3: // Connection update
			c.metrics.RecordBytesTransferred("rx", float64(event.Info.RxBytes))
			c.metrics.RecordBytesTransferred("tx", float64(event.Info.TxBytes))
		}
	})
	if err != nil {
		klog.Errorf("Event processing stopped: %v", err)
	}
}

// runWorker processes items from the work queue
func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem processes a single item from the work queue
func (c *Controller) processNextItem() bool {
	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(obj)

	err := c.syncConfig(obj.(string))
	if err != nil {
		c.queue.AddRateLimited(obj)
		klog.Errorf("Error syncing config %q: %v", obj, err)
		return true
	}

	c.queue.Forget(obj)
	return true
}

// syncConfig synchronizes the desired state with the current state
func (c *Controller) syncConfig(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	// Get the config
	obj, exists, err := c.client.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("fetching object with key %s: %v", key, err)
	}

	if !exists {
		klog.V(2).Infof("Config %s/%s deleted", namespace, name)
		return nil
	}

	config := obj.(*conntrackv1alpha1.ConntrackConfig)
	klog.V(2).Infof("Syncing config %s/%s", namespace, name)

	// Update BPF maps
	if err := c.mapUpdater.UpdateFilters(config); err != nil {
		return fmt.Errorf("updating filters: %w", err)
	}

	// Update metrics
	c.metrics.RecordConfigUpdate("success")

	return nil
}

// enqueueConfig adds a config to the work queue
func (c *Controller) enqueueConfig(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.queue.Add(key)
}
