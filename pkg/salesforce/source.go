// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package salesforce

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/grpcclient/"
)


func (p *Plugin) initInstance(oCtx *PluginInstance) error {
	oCtx.grpcChannel = nil

	return nil
}

// Open an event stream and return an open plugin instance.
func (p *Plugin) Open(params string) (source.Instance, error) {
	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}
	
	oCtx.grpcChannel = make(chan []byte, 128)

	// Launch the GRPC client
	go grpcclient.CreateGRPCClient(p, oCtx)

	return oCtx, nil
}

// Closing the event stream and deinitialize the open plugin instance.
func (o *PluginInstance) Close() {
	// Shut down the GRPC Client
	
}

// Produce and return a new batch of events.
func (o *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Casting to our plugin type
	pCtx := pState.(*Plugin)

	// Batching is not supported for now, so we only write the first entry of the batch
	evt := evts.Get(0)
	writer := evt.Writer()

	// Receive the event from the webserver channel with a 1 sec timeout
	var data []byte
	afterCh := time.After(1 * time.Second)
	select {
	case data = <-o.grpcChannel:
	case <-afterCh:
		pCtx.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// Write data inside the event
	written, err := writer.Write(data)
	if err != nil {
		return 0, err
	}
	if written < len(data) {
		return 0, fmt.Errorf("salesforce message too long: %d, max %d supported", len(data), written)
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

