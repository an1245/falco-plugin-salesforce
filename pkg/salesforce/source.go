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
	"errors"
	
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/common"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/proto"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/grpcclient"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
)


func (p *Plugin) initInstance(oCtx *PluginInstance) error {

	// think of plugin_init as initializing the plugin software
	
	oCtx.loginChannel = nil
	oCtx.logoutChannel = nil
	oCtx.loginAsChannel = nil
	oCtx.sessionHijackingChannel = nil
	oCtx.credentialStuffingChannel = nil
	oCtx.permissionSetChannel = nil
	oCtx.apiAnomalyChannel = nil
	
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

	log.Printf("Salesforce Plugin: Debug logging is enabled?: %v", p.config.Debug)
	
	oCtx.loginChannel = make(chan []byte, 128)
	oCtx.logoutChannel = make(chan []byte, 128)
	oCtx.loginAsChannel = make(chan []byte, 128)
	oCtx.sessionHijackingChannel = make(chan []byte, 128)
	oCtx.credentialStuffingChannel = make(chan []byte, 128)
	oCtx.permissionSetChannel = make(chan []byte, 128)
	oCtx.apiAnomalyChannel = make(chan []byte, 128)

	// Launch the GRPC client
	oCtx.pubSubClient = CreateGRPCClientConnection(p, oCtx)
	
	
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.LoginTopic, common.LoginTopicEventType, oCtx.loginChannel)
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.LogoutTopic, common.LogoutTopicEventType, oCtx.logoutChannel)	
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.LoginAsTopic, common.LoginAsTopicEventType, oCtx.loginAsChannel)
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.SessionHijackingTopic, common.SessionHijackingEventType, oCtx.sessionHijackingChannel)
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.CredentialStuffingTopic, common.CredentialStuffingEventType, oCtx.credentialStuffingChannel)
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.PermissionSetEventTopic, common.PermissionSetEventType, oCtx.permissionSetChannel)
	go subscribeGRPCTopic(p, oCtx, oCtx.pubSubClient, common.ApiAnomalyEventTopic, common.ApiAnomalyEventType, oCtx.apiAnomalyChannel)
	
	return oCtx, nil
}

func exitWithError(oCtx *PluginInstance, err error) {
	oCtx.pubSubClient.Close()
	log.Fatalf("Salesforce Plugin ERROR: Exiting with Error: %v", err)
}

// Closing the event stream and deinitialize the open plugin instance.
func (oCtx *PluginInstance) Close() {
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
	var sessionhijackdata []byte
	var credentialstuffdata []byte
	var permissionsetdata []byte
	var apiAnomalydata []byte
	
	afterCh := time.After(1 * time.Second)
	select {
	case logindata = <-o.loginChannel:
		// Process LoginData
		written, err := writer.Write(logindata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Login Event data events - %v", err)
		}
		if written < len(logindata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: logindata message too long: %d, max %d supported", len(logindata), written)
		}
	case logoutdata = <-o.logoutChannel:
		// Process LogoutData
		written, err := writer.Write(logoutdata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Logout Event data events - %v", err)
		}
		if written < len(logoutdata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: logoutdata message too long: %d, max %d supported", len(logoutdata), written)
		}
	case loginasdata = <-o.loginAsChannel:
		// Process LoginAsData
		written, err := writer.Write(loginasdata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Login As Event data events - %v", err)
		}
		if written < len(loginasdata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: loginasdata message too long: %d, max %d supported", len(loginasdata), written)
		}
	case sessionhijackdata = <-o.sessionHijackingChannel:
		// Process sessionhijackdata
		written, err := writer.Write(sessionhijackdata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Session Hijack Event data events - %v", err)
		}
		if written < len(sessionhijackdata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: sessionhijackdata message too long: %d, max %d supported", len(sessionhijackdata), written)
		}
	case credentialstuffdata = <-o.credentialStuffingChannel:
		// Process credentialstuffdata
		written, err := writer.Write(credentialstuffdata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Credential Stuffing Event data events - %v", err)
		}
		if written < len(credentialstuffdata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: credentialstuffdata message too long: %d, max %d supported", len(credentialstuffdata), written)
		}
	case permissionsetdata = <-o.permissionSetChannel:
		// Process permissionsetdata
		written, err := writer.Write(permissionsetdata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write Permission Set Event data events - %v", err)
		}
		if written < len(permissionsetdata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: permissionsetdata message too long: %d, max %d supported", len(permissionsetdata), written)
		}
	case apiAnomalydata = <-o.apiAnomalyChannel:
		// Process apiAnomalydata
		written, err := writer.Write(apiAnomalydata)
		if err != nil {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: Couldn't write API Anomaly Event data events - %v", err)
		}
		if written < len(apiAnomalydata) {
			return 0, fmt.Errorf("Salesforce Plugin ERROR: apiAnomalydata message too long: %d, max %d supported", len(permissionsetdata), written)
		}
	case <-afterCh:
		pCtx.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

func CreateGRPCClientConnection(p *Plugin, oCtx *PluginInstance) (*grpcclient.PubSubClient){
	if common.ReplayPreset == proto.ReplayPreset_CUSTOM && common.ReplayId == nil {
		log.Printf("Salesforce Plugin ERROR: the replayId variable must be populated when the replayPreset variable is set to CUSTOM")
		err := errors.New("the replayId variable must be populated when the replayPreset variable is set to CUSTOM")
		exitWithError(oCtx, err)
	} else if common.ReplayPreset != proto.ReplayPreset_CUSTOM && common.ReplayId != nil {
		log.Printf("the replayId variable must not be populated when the replayPreset variable is set to EARLIEST or LATEST")
		err := errors.New("the replayId variable must not be populated when the replayPreset variable is set to EARLIEST or LATEST")
		exitWithError(oCtx, err)
	}

	if (p.config.Debug){
		log.Printf("Salesforce Plugin: Creating gRPC client...")
	}
	
	client, err := grpcclient.NewGRPCClient(p.config.Debug)
	if err != nil {
		log.Printf("Salesforce Plugin ERROR: could not create gRPC client: %v", err)
		exitWithError(oCtx, err)
	}

	if (p.config.Debug){
		log.Printf("Salesforce Plugin: Populating auth token...")
		
	}
	
	err = client.Authenticate(p.config.SFDCClientId, p.config.SFDCClientSecret, p.config.SFDCLoginURL)
	if err != nil {
		
		log.Printf("Salesforce Plugin ERROR: could not authenticate - check your Client ID and Secret in falco.yaml - %v", err)
		exitWithError(oCtx, err)
	}

	if (p.config.Debug){
		log.Printf("Salesforce Plugin: Populating user info...")
	}
	err = client.FetchUserInfo(p.config.SFDCLoginURL)
	if err != nil {
		log.Printf("Salesforce Plugin ERROR: could not fetch user info: %v", err)
		exitWithError(oCtx, err)
	}

	return client
}

func subscribeGRPCTopic(p *Plugin, oCtx *PluginInstance, client *grpcclient.PubSubClient, Topic string, eventType string, channel chan []byte) (error){

	if (p.config.Debug){
		log.Printf("Salesforce Plugin: Making GetTopic request...")
	}
	topic, err := client.GetTopic(Topic)
	if err != nil {
		log.Printf("Salesforce Plugin ERROR: could not fetch topic: %v", err)
		exitWithError(oCtx, err)
	}

	if !topic.GetCanSubscribe() {
		log.Printf("Salesforce Plugin ERROR: this user is not allowed to subscribe to the following topic: %s", Topic)
		exitWithError(oCtx, err)
	}

	curReplayId := common.ReplayId
	backoffcount := 1

	for {
		
		if (p.config.Debug){
			log.Printf("Salesforce Plugin: Subscribing to topic: %s", Topic)
		}

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
			if (!processErrorCodeBackoff(err) && backoffcount <= 40) {
				log.Printf("Salesforce Plugin WARNING: error occurred while subscribing to topic - sleeping for %d min", backoffcount*5)
				time.Sleep(time.Duration(backoffcount * 5) * time.Minute)
				backoffcount += 1
			} else {
				fmt.Errorf("Salesforce Plugin ERROR: error occurred while subscribing to topic: - still existed after 30 mis - exiting..")
				exitWithError(oCtx, err)
			}
			
		}
	}

}


func processErrorCodeBackoff(err error) bool {
	
	// Processes Error code and decides whether to exit immediately of back off
	// returns true to exit immediately
	// returns false to backoff

	switch status.Code(err) {
	case codes.Canceled:
		return false
	case codes.Unknown:
		return false
	case codes.InvalidArgument:
		return false
	case codes.DeadlineExceeded:
		return false
	case codes.NotFound:
		return false
	case codes.AlreadyExists:
		return false
	case codes.PermissionDenied:
		return false
	case codes.ResourceExhausted:
		return false
	case codes.FailedPrecondition:
		return false
	case codes.Aborted:
		return false
	case codes.OutOfRange:
		return false
	case codes.Unimplemented:
		return true
	case codes.Internal:
		return false
	case codes.Unavailable:
		return false
	case codes.DataLoss: 
		return false
	case codes.Unauthenticated:
		return true
	default:
		return false
	}

}

