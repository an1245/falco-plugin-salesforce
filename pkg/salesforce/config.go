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


// PluginConfig represents a configuration of the GitHub plugin
type PluginConfig struct {
	SFDCClientId           string `json:"sfdcclientid" jsonschema:"title=Salesforce Connect App Client Id"`
	SFDCClientSecret       string `json:"sfdcclientsecret" jsonschema:"title=Salesforce Connect App Client Secret"`
	SFDCLoginURL 	       string `json:"sfdcloginurl" jsonschema:"title=Salesforce Login URL (i.e. MyDomainName.my.salesforce.com) - refer: https://help.salesforce.com/s/articleView?id=sf.domain_name_hostnames.htm&type=5"`
	Debug                  bool   `json:"Debug" jsonschema:"title=Enable debug output (true = yes, false=no)"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {

	
}
