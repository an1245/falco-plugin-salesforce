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
	"fmt"
	"math"
	"time"
	"log"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/common"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/proto"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/grpcclient"
)


func (p *Plugin) initInstance(oCtx *PluginInstance) error {

	// think of plugin_init as initializing the plugin software
	
	oCtx.grpcChannel = nil
	return nil
}

// Open an event stream and return an open plugin instance.
func (p *Plugin) Open(params string) (source.Instance, error) {
	
	// think of plugin_open as configuring the software to return events
	
	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}
	
	oCtx.grpcChannel = make(chan []byte, 128)

	// Launch the GRPC client
	go CreateGRPCClient(p, oCtx)

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

func CreateGRPCClient(p *Plugin, oCtx *PluginInstance) {
	if common.ReplayPreset == proto.ReplayPreset_CUSTOM && common.ReplayId == nil {
		log.Fatalf("the replayId variable must be populated when the replayPreset variable is set to CUSTOM")
	} else if common.ReplayPreset != proto.ReplayPreset_CUSTOM && common.ReplayId != nil {
		log.Fatalf("the replayId variable must not be populated when the replayPreset variable is set to EARLIEST or LATEST")
	}

	
	log.Printf("Creating gRPC client...")
	
	client, err := grpcclient.NewGRPCClient()
	if err != nil {
		log.Fatalf("could not create gRPC client: %v", err)
	}
	defer client.Close()
	
	log.Printf("Populating auth token...")
	err = client.Authenticate(p.config.SFDCClientId, p.config.SFDCClientSecret, p.config.SFDCLoginURL)
	if err != nil {
		client.Close()
		log.Fatalf("could not authenticate: %v", err)
	}

	log.Printf("Populating user info...")
	err = client.FetchUserInfo(p.config.SFDCLoginURL)
	if err != nil {
		client.Close()
		log.Fatalf("could not fetch user info: %v", err)
	}

	log.Printf("Making GetTopic request...")
	topic, err := client.GetTopic()
	if err != nil {
		client.Close()
		log.Fatalf("could not fetch topic: %v", err)
	}

	if !topic.GetCanSubscribe() {
		client.Close()
		log.Fatalf("this user is not allowed to subscribe to the following topic: %s", common.TopicName)
	}

	curReplayId := common.ReplayId
	for {
		log.Printf("Subscribing to topic...")

		// use the user-provided ReplayPreset by default, but if the curReplayId variable has a non-nil value then assume that we want to
		// consume from a custom offset. The curReplayId will have a non-nil value if the user explicitly set the ReplayId or if a previous
		// subscription attempt successfully processed at least one event before crashing
		replayPreset := common.ReplayPreset
		if curReplayId != nil {
			replayPreset = proto.ReplayPreset_CUSTOM
		}

		// In the happy path the Subscribe method should never return, it will just process events indefinitely. In the unhappy path
		// (i.e., an error occurred) the Subscribe method will return both the most recently processed ReplayId as well as the error message.
		// The error message will be logged for the user to see and then we will attempt to re-subscribe with the ReplayId on the next iteration
		// of this for loop
		curReplayId, err = client.Subscribe(replayPreset, curReplayId, oCtx.grpcChannel)
		if err != nil {
			log.Printf("error occurred while subscribing to topic: %v", err)
		}
	}
}


