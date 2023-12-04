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
	
	oCtx.loginChannel = nil
	oCtx.logoutChannel = nil
	oCtx.loginAsChannel = nil
	
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

	log.Printf("Debug logging is: %s", p.config.debug)
	
	oCtx.loginChannel = make(chan []byte, 128)
	oCtx.logoutChannel = make(chan []byte, 128)
	oCtx.loginAsChannel = make(chan []byte, 128)

	// Launch the GRPC client
	client := CreateGRPCClientConnection(p, oCtx)
	
	go subscribeGRPCTopic(p, oCtx, client, common.LoginTopic, common.LoginTopicEventType, oCtx.loginChannel)
	go subscribeGRPCTopic(p, oCtx, client, common.LogoutTopic, common.LogoutTopicEventType, oCtx.logoutChannel)
	go subscribeGRPCTopic(p, oCtx, client, common.LoginAsTopic, common.LoginAsTopicEventType, oCtx.loginAsChannel)
	
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
	var logindata []byte
	var logoutdata []byte
	var loginasdata []byte
	
	afterCh := time.After(1 * time.Second)
	select {
	case logindata = <-o.loginChannel:
	case logoutdata = <-o.logoutChannel:
	case loginasdata = <-o.loginAsChannel:
	case <-afterCh:
		pCtx.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// Write data inside the event
	written, err := writer.Write(logindata)
	if err != nil {
		return 0, err
	}
	if written < len(logindata) {
		return 0, fmt.Errorf("salesforce message too long: %d, max %d supported", len(logindata), written)
	}

	written, err = writer.Write(logoutdata)
	if err != nil {
		return 0, err
	}
	if written < len(logoutdata) {
		return 0, fmt.Errorf("salesforce message too long: %d, max %d supported", len(logoutdata), written)
	}

	written, err = writer.Write(loginasdata)
	if err != nil {
		return 0, err
	}
	if written < len(loginasdata) {
		return 0, fmt.Errorf("salesforce message too long: %d, max %d supported", len(loginasdata), written)
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

func CreateGRPCClientConnection(p *Plugin, oCtx *PluginInstance) (*grpcclient.PubSubClient){
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
	//defer client.Close()

	log.Printf("connection type: %T", client)
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

	return client
}

func subscribeGRPCTopic(p *Plugin, oCtx *PluginInstance, client *grpcclient.PubSubClient, Topic string, eventType string, channel chan []byte){

	log.Printf("Making GetTopic request...")
	topic, err := client.GetTopic(Topic)
	if err != nil {
		client.Close()
		log.Fatalf("could not fetch topic: %v", err)
	}

	if !topic.GetCanSubscribe() {
		client.Close()
		log.Fatalf("this user is not allowed to subscribe to the following topic: %s", Topic)
	}

	curReplayId := common.ReplayId
	for {
		log.Printf("Subscribing to topic: %s", Topic)

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
		curReplayId, err = client.Subscribe(replayPreset, curReplayId, channel, Topic, eventType)
		if err != nil {
			log.Printf("error occurred while subscribing to topic: %v", err)
		}
	}

}


