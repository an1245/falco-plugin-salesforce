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
	"encoding/json"
	"github.com/alecthomas/jsonschema"
	"github.com/valyala/fastjson"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/grpcclient"
)

const (
	PluginID           uint32 = 999
	PluginName                = "salesforce"
	PluginDescription         = "Reads events from Salesforce using GRPC Connection"
	PluginContact             = "github.com/falcosecurity/plugins"
	PluginVersion             = "0.1.0"
	PluginEventSource         = "salesforce"
	ExtractEventSource        = "salesforce"
)


// Plugin represent the Salesforce plugin
type Plugin struct {
	plugins.BasePlugin
	config      PluginConfig
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
}

// PluginInstance represents an opened instance of the plugin,
// which is returned by Open() and deinitialized during Close().
type PluginInstance struct {
	source.BaseInstance
	loginChannel      chan []byte
	logoutChannel      chan []byte
	loginAsChannel      chan []byte
	sessionHijackingChannel      chan []byte
	credentialStuffingChannel    chan []byte
	permissionSetChannel	chan []byte
	apiAnomalyChannel	chan []byte
	pubSubClient	grpcclient.PubSubClient
}

// Return the plugin info to the framework.
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  PluginID,
		Name:                PluginName,
		Description:         PluginDescription,
		Contact:             PluginContact,
		Version:             PluginVersion,
		EventSource:         PluginEventSource,
		ExtractEventSources: []string{ExtractEventSource},
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: false, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}

	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}

	return nil
}

// Initialize the plugin state.
func (p *Plugin) Init(cfg string) error {
	
	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.Reset()
	json.Unmarshal([]byte(cfg), &p.config)
	

	return nil
}
