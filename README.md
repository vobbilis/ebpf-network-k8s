# eBPF Network Monitoring for Kubernetes

A Kubernetes-native network monitoring and filtering solution using eBPF. This project provides real-time connection tracking, network filtering, and performance metrics collection for Kubernetes workloads.

## Features

- Real-time connection tracking for TCP and UDP traffic
- Network filtering based on IP addresses, ports, and protocols
- Performance metrics collection (retransmissions, errors, etc.)
- Kubernetes Custom Resource Definition (CRD) for configuration
- Prometheus metrics integration

## Components

### BPF Programs

- `conntrack.bpf.c`: Main BPF program for connection tracking and filtering
- TCP state tracking
- UDP flow monitoring
- Retransmission detection
- Ingress/Egress packet monitoring

### Configuration

- Custom Resource Definition (CRD) for defining filtering rules
- Support for IPv4/IPv6 addresses
- Port range filtering
- Protocol-specific rules (TCP/UDP)

### Metrics

- Connection statistics
- TCP state transitions
- Retransmission metrics
- Filter rule effectiveness
- Performance metrics

## Requirements

- Linux kernel 5.4 or later
- Kubernetes 1.19 or later
- BPF CO-RE support

## Installation

TODO: Add installation instructions

## Usage

TODO: Add usage examples and configuration guide

## License

GPL 