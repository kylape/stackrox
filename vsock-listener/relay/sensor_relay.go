package relay

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/internalapi/sensor"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/clientconn"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/mtls"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	log = logging.LoggerForModule()
)

// VMData represents data received from a VM
type VMData struct {
	VMUID       string
	VMName      string
	VMNamespace string
	MessageType uint32
	Data        []byte
	Timestamp   time.Time
}

// VulmaVirtualMachine represents the JSON structure sent by the vulma agent
type VulmaVirtualMachine struct {
	Scan *VulmaScan `json:"scan,omitempty"`
}

// VulmaScan represents scan data from vulma agent
type VulmaScan struct {
	Components []*storage.EmbeddedImageScanComponent `json:"components,omitempty"`
}

// SensorRelay manages communication with the sensor
type SensorRelay struct {
	ctx        context.Context
	cancel     context.CancelFunc
	sensorAddr string
	conn       *grpc.ClientConn
	client     sensor.VirtualMachineServiceClient
	stopper    concurrency.Stopper
	dataChan   chan *VMData
	wg         sync.WaitGroup
}

// NewSensorRelay creates a new sensor relay
func NewSensorRelay(ctx context.Context, sensorAddr string) (*SensorRelay, error) {
	ctx, cancel := context.WithCancel(ctx)

	return &SensorRelay{
		ctx:        ctx,
		cancel:     cancel,
		sensorAddr: sensorAddr,
		stopper:    concurrency.NewStopper(),
		dataChan:   make(chan *VMData, 100), // Buffer for 100 messages
	}, nil
}

// Start starts the sensor relay
func (r *SensorRelay) Start() error {
	log.Infof("Starting sensor relay to %s", r.sensorAddr)

	// Create gRPC connection to sensor
	conn, err := r.createSensorConnection()
	if err != nil {
		return errors.Wrap(err, "failed to create sensor connection")
	}
	r.conn = conn

	// Create VirtualMachine service client
	r.client = sensor.NewVirtualMachineServiceClient(conn)

	// Start processing messages
	r.wg.Add(1)
	go r.processMessages()

	log.Info("Sensor relay started")
	return nil
}

// Stop stops the sensor relay
func (r *SensorRelay) Stop() error {
	log.Info("Stopping sensor relay...")

	r.cancel()
	r.stopper.Client().Stop()

	// Close connection
	if r.conn != nil {
		if err := r.conn.Close(); err != nil {
			log.Warnf("Error closing sensor connection: %v", err)
		}
	}

	// Close data channel
	close(r.dataChan)

	// Wait for processing to finish
	r.wg.Wait()

	log.Info("Sensor relay stopped")
	return nil
}

// SendVMData sends VM data to the sensor
func (r *SensorRelay) SendVMData(data *VMData) error {
	select {
	case r.dataChan <- data:
		return nil
	case <-r.ctx.Done():
		return r.ctx.Err()
	default:
		return errors.New("data channel full, dropping message")
	}
}

// createSensorConnection creates a gRPC connection to the sensor
func (r *SensorRelay) createSensorConnection() (*grpc.ClientConn, error) {
	clientconn.SetUserAgent("Rox VSOCK Listener")

	// Use VM agent certificates for authentication
	// Note: In a real implementation, you'd need appropriate certificates
	opts, err := clientconn.OptionsForEndpoint(r.sensorAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "creating connection options for %s", r.sensorAddr)
	}

	conn, err := clientconn.GRPCConnection(
		r.ctx,
		mtls.VSOCKListenerSubject,
		r.sensorAddr,
		opts,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "creating gRPC connection to sensor at %s", r.sensorAddr)
	}

	return conn, nil
}

// processMessages processes VM data messages and sends them to sensor
func (r *SensorRelay) processMessages() {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		case data, ok := <-r.dataChan:
			if !ok {
				return // Channel closed
			}

			if err := r.sendToSensor(data); err != nil {
				log.Errorf("Failed to send VM data to sensor: %v", err)
				// In a production system, you might want to retry or queue failed messages
			}
		}
	}
}

// sendToSensor sends VM data to the sensor
func (r *SensorRelay) sendToSensor(data *VMData) error {
	// Convert VMData to protobuf message
	vmMessage := r.convertToVMMessage(data)

	// Send to sensor using existing VM service
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()

	// Use the existing VirtualMachine service to send data
	// This assumes the sensor has been extended to handle VM data messages
	_, err := r.client.UpsertVirtualMachine(ctx, &sensor.UpsertVirtualMachineRequest{
		VirtualMachine: vmMessage,
	})

	if err != nil {
		return errors.Wrap(err, "failed to send VM message to sensor")
	}

	log.Debugf("Sent VM data for %s/%s to sensor", data.VMNamespace, data.VMName)
	return nil
}

// convertToVMMessage converts VMData to a storage.VirtualMachine protobuf message
func (r *SensorRelay) convertToVMMessage(data *VMData) *storage.VirtualMachine {
	now := timestamppb.New(data.Timestamp)

	// Create base VM message using the actual protobuf structure
	vm := &storage.VirtualMachine{
		Id:          data.VMUID,
		Name:        data.VMName,
		Namespace:   data.VMNamespace,
		LastUpdated: now,
	}

	// Handle different message types
	switch data.MessageType {
	case 1: // Package data
		// Parse JSON package data from vulma agent
		var vulmaVM VulmaVirtualMachine
		if err := json.Unmarshal(data.Data, &vulmaVM); err != nil {
			log.Errorf("Failed to parse VM data from %s: %v", data.VMName, err)
			return vm
		}

		// Convert vulma scan data to storage format
		if vulmaVM.Scan != nil {
			vm.Scan = &storage.VirtualMachineScan{
				ScanTime:       now,
				ScannerVersion: "vulma-0.1.0", // Version from vulma agent
				Components:     vulmaVM.Scan.Components,
				// TODO: Add operating system detection
				// OperatingSystem: detectOS(vulmaVM.Scan.Components),
			}
		}

		if vm.Scan != nil {
			log.Debugf("Processed %d components for VM %s", len(vm.Scan.Components), data.VMName)
		}

	case 2: // System info
		// Parse system info and populate VM fields
		log.Debugf("Processing system info for VM %s", data.VMName)

	default:
		log.Warnf("Unknown message type %d from VM %s", data.MessageType, data.VMName)
	}

	return vm
}

