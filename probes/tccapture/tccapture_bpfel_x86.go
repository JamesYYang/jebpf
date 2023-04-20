// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package tccapture

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tccaptureNetPacketEvent struct {
	Ts      uint64
	Len     uint32
	Ifindex uint32
	Sip     uint32
	Dip     uint32
	Sport   uint16
	Dport   uint16
	Ingress uint16
	_       [2]byte
}

// loadTccapture returns the embedded CollectionSpec for tccapture.
func loadTccapture() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TccaptureBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tccapture: %w", err)
	}

	return spec, err
}

// loadTccaptureObjects loads tccapture and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tccaptureObjects
//	*tccapturePrograms
//	*tccaptureMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTccaptureObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTccapture()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tccaptureSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tccaptureSpecs struct {
	tccaptureProgramSpecs
	tccaptureMapSpecs
}

// tccaptureSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tccaptureProgramSpecs struct {
	EgressClsFunc  *ebpf.ProgramSpec `ebpf:"egress_cls_func"`
	IngressClsFunc *ebpf.ProgramSpec `ebpf:"ingress_cls_func"`
}

// tccaptureMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tccaptureMapSpecs struct {
	TcCaptureEvents *ebpf.MapSpec `ebpf:"tc_capture_events"`
}

// tccaptureObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTccaptureObjects or ebpf.CollectionSpec.LoadAndAssign.
type tccaptureObjects struct {
	tccapturePrograms
	tccaptureMaps
}

func (o *tccaptureObjects) Close() error {
	return _TccaptureClose(
		&o.tccapturePrograms,
		&o.tccaptureMaps,
	)
}

// tccaptureMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTccaptureObjects or ebpf.CollectionSpec.LoadAndAssign.
type tccaptureMaps struct {
	TcCaptureEvents *ebpf.Map `ebpf:"tc_capture_events"`
}

func (m *tccaptureMaps) Close() error {
	return _TccaptureClose(
		m.TcCaptureEvents,
	)
}

// tccapturePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTccaptureObjects or ebpf.CollectionSpec.LoadAndAssign.
type tccapturePrograms struct {
	EgressClsFunc  *ebpf.Program `ebpf:"egress_cls_func"`
	IngressClsFunc *ebpf.Program `ebpf:"ingress_cls_func"`
}

func (p *tccapturePrograms) Close() error {
	return _TccaptureClose(
		p.EgressClsFunc,
		p.IngressClsFunc,
	)
}

func _TccaptureClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tccapture_bpfel_x86.o
var _TccaptureBytes []byte
