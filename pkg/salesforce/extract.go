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
	"io/ioutil"
	"fmt"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// Return the fields supported for extraction.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "salesforce.eventtype", Display: "Event Type", Desc: "What type of SFDC event was this?"},
		{Type: "string", Name: "salesforce.acceptlanguage", Display: "Accept Language", Desc: "List of HTTP Headers that specify the natural language, such as English, that the client understands."},
		{Type: "string", Name: "salesforce.application", Display: "Login Application", Desc: "How the user has logged in (browser, api etc.)"},
		{Type: "string", Name: "salesforce.browser", Display: "Browser Type", Desc: "What browser did the user log in with?"},
		{Type: "string", Name: "salesforce.city", Display: "City", Desc: "Which city did the user log in from?"},
		{Type: "string", Name: "salesforce.country", Display: "Country", Desc: "Which country did the user log in from?"},
		{Type: "string", Name: "salesforce.countryiso", Display: "Country ISO", Desc: "Which country did the user log in from? in ISO Format"},
		{Type: "string", Name: "salesforce.currentip", Display: "Current Hijacked IP", Desc: "What is the current IP of the hijacked session"},
		{Type: "string", Name: "salesforce.currentplatform", Display: "Current Hijacked Platform", Desc: "What is the current platform that the hijacked session"},
		{Type: "string", Name: "salesforce.currentscreen", Display: "Current Hijacked Screen", Desc: "What is the current screen that the hijacked session"},
		{Type: "string", Name: "salesforce.currentuseragent", Display: "Current Hijacked UserAgent", Desc: "What is the current user agent that the hijacked session"},
		{Type: "string", Name: "salesforce.currentwindow", Display: "Current Hijacked Window", Desc: "What is the current window that the hijacked session"},
		{Type: "string", Name: "salesforce.delegatedusername", Display: "Delegated Username", Desc: "This user assumed login as another user"},
		{Type: "string", Name: "salesforce.delegatedorganizationid", Display: "Delegated Organisation", Desc: "Organsiation name of a user that assumed login as another user"},
		{Type: "string", Name: "salesforce.evaluationtime", Display: "Evaluation Time", Desc: "The amount of time it took to evaluate the policy in milliseconds"},
		{Type: "string", Name: "salesforce.eventdate", Display: "Event Date", Desc: "What date/time was this event generated?"},
		{Type: "string", Name: "salesforce.eventidentifier", Display: "Event Identifier", Desc: "What is the event identifier of this event?"},
		{Type: "string", Name: "salesforce.eventuuid", Display: "Event UUID", Desc: "What is the event uuid of this event?"},
		{Type: "string", Name: "salesforce.eventsource", Display: "Event Source", Desc: "What is the source of the event"},
		{Type: "string", Name: "salesforce.hasexternalusers", Display: "Has External Users", Desc: "Does the permission change impact external users"},
		{Type: "string", Name: "salesforce.httpmethod", Display: "HTTP Method", Desc: "What HTTP Method was the user using when event was generated?"},
		{Type: "string", Name: "salesforce.impacteduserids", Display: "External Users Impacted", Desc: "What external users were affected by the permission change"},
		{Type: "string", Name: "salesforce.logingeoid", Display: "Login Geo ID", Desc: "What Geo ID did the user log in from?"},
		{Type: "string", Name: "salesforce.loginhistoryid", Display: "Login History ID", Desc: "What is the login history ID"},
		{Type: "string", Name: "salesforce.loginlatitude", Display: "Login Latitude", Desc: "What Latitude did the user log in from?"},
		{Type: "string", Name: "salesforce.loginlongitude", Display: "Login Longitude", Desc: "What Longitude did the user log in from?"},
		{Type: "string", Name: "salesforce.loginkey", Display: "Login Key", Desc: "he string that ties together all events in a given user’s login session."},
		{Type: "string", Name: "salesforce.logintype", Display: "Login Type", Desc: "What type of login was this? (i.e. Application)"},
		{Type: "string", Name: "salesforce.loginurl", Display: "Login URL", Desc: "What login URL did was the user using?"},
		{Type: "string", Name: "salesforce.operation", Display: "Operation", Desc: "The API call that generated the event. For example, Query."},
		{Type: "string", Name: "salesforce.parentidlist", Display: "Parent ID List", Desc: "IDs affected by the permisson change"},
		{Type: "string", Name: "salesforce.parentnamelist", Display: "Permission Sets affected", Desc: "Names of affected permssion sets"},
		{Type: "string", Name: "salesforce.platform", Display: "Login Platform", Desc: "What platform was the user using when they logged in? (i.e. Windows 10)"},
		{Type: "string", Name: "salesforce.postalcode", Display: "Login Postal Code", Desc: "What postal code did the user log in from?"},
		{Type: "string", Name: "salesforce.previousip", Display: "Previous Hijacked IP", Desc: "What is the IP of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previousscreen", Display: "Previous Hijacked Screen", Desc: "What is the screen of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previousplatform", Display: "Previous Hijacked Platform ", Desc: "What is the platform of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previoususeragent", Display: "Previous Hijacked User Agent", Desc: "What is the user agent of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previouswindow", Display: "Previous Hijacked Window", Desc: "What is the window of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.queriedentities", Display: "Queried Entities", Desc: "The type of entities associated with the event."},
		{Type: "string", Name: "salesforce.requestidentifier", Display: "API transaction ID", Desc: "The unique ID of a single transaction."},
		{Type: "string", Name: "salesforce.rowsprocessed", Display: "Rows Proessed in transaction", Desc: "Total row count for the current operation"},
		{Type: "string", Name: "salesforce.score", Display: "Security Event Score", Desc: "score for the API execution or export tracked by this event - 0 low and 100 high"},
		{Type: "string", Name: "salesforce.securityeventdata", Display: "Hijacking Security Event Data", Desc: "What is the security event data of the hijacked session"},
		{Type: "string", Name: "salesforce.sessionlevel", Display: "Session Level", Desc: "What level was this session? (Standard etc.)"},
		{Type: "string", Name: "salesforce.sessionkey", Display: "Session Key", Desc: "What was the session key of the session?"},
		{Type: "string", Name: "salesforce.sourceip", Display: "Source IP", Desc: "What was the source IP that the user logged in from?"},
		{Type: "string", Name: "salesforce.summary", Display: "Text Summary", Desc: "A text summary of the threat that caused this event to be created. "},
		{Type: "string", Name: "salesforce.loginstatus", Display: "Login Status", Desc: "What was the status of the login? (success etc.)"},
		{Type: "string", Name: "salesforce.subdivision", Display: "Login Subdivision", Desc: "What subdivision did the user log in from?"},
		{Type: "string", Name: "salesforce.targeturl", Display: "Target URL", Desc: "The target URL that was accessed"},
		{Type: "string", Name: "salesforce.tlsprotocol", Display: "TLS Protocol", Desc: "What TLS protocol was the user using?"},
		{Type: "string", Name: "salesforce.useragent", Display: "User Agent", Desc: "The User-Agent header of the HTTP request of the unauthorized login."},
		{Type: "string", Name: "salesforce.userid", Display: "User ID", Desc: "What was the users ID?"},
		{Type: "string", Name: "salesforce.usertype", Display: "User Type", Desc: "What type of user was this? (i.e. Standard)"},
		{Type: "string", Name: "salesforce.username", Display: "Username", Desc: "What was the users username?"},
		{Type: "string", Name: "salesforce.uri", Display: "Page URI", Desc: "The URI of the page that’s receiving the request."},
	}
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "salesforce.eventtype":
		res = string(jdata.GetStringBytes("EventType"))
	case "salesforce.acceptlanguage":
		res = string(jdata.GetStringBytes("AcceptLanguage"))
	case "salesforce.application":
		res = string(jdata.GetStringBytes("Application"))
	case "salesforce.browser":
		res = string(jdata.GetStringBytes("Browser"))
	case "salesforce.city":
		res = string(jdata.GetStringBytes("City"))
	case "salesforce.country":
		res = string(jdata.GetStringBytes("Country"))
	case "salesforce.countryiso":
		res = string(jdata.GetStringBytes("CountryIso"))
	case "salesforce.currentip":
		res = string(jdata.GetStringBytes("CurrentIp"))
	case "salesforce.currentplatform":
		res = string(jdata.GetStringBytes("CurrentPlatform"))
	case "salesforce.currentscreen":
		res = string(jdata.GetStringBytes("CurrentScreen"))
	case "salesforce.currentuseragent":
		res = string(jdata.GetStringBytes("CurrentUserAgent"))
	case "salesforce.currentwindow":
		res = string(jdata.GetStringBytes("CurrentWindow"))
	case "salesforce.delegatedusername":
		res = string(jdata.GetStringBytes("DelegatedUsername"))
	case "salesforce.delegatedorganizationid":
		res = string(jdata.GetStringBytes("DelegatedOrganizationId"))
	case "salesforce.evaluationtime":
		res = fmt.Sprintf("%f",jdata.GetStringBytes("EvaluationTime"))
	case "salesforce.eventdate":
		res = fmt.Sprintf("%f",jdata.GetStringBytes("EventDate"))
	case "salesforce.eventidentifier":
		res = string(jdata.GetStringBytes("EventIdentifier"))
	case "salesforce.eventuuid":
		res = string(jdata.GetStringBytes("EventUuid"))
	case "salesforce.eventsource":
		res = string(jdata.GetStringBytes("EventSource"))
	case "salesforce.hasexternalusers":
		//res = string(jdata.GetStringBytes("HttpMethod"))
	case "salesforce.httpmethod":
		res = string(jdata.GetStringBytes("HttpMethod"))
	case "salesforce.impacteduserids":
		res = string(jdata.GetStringBytes("ImpactedUserIds"))
	case "salesforce.logingeoid":
		res = string(jdata.GetStringBytes("LoginGeoId"))
	case "salesforce.loginhistoryid":
		res = string(jdata.GetStringBytes("LoginHistoryId"))
	case "salesforce.loginlatitude":
		//res = float64(jdata.GetFloat64("LoginLatitude"))
	case "salesforce.loginlongitude":
		//res = float64(jdata.GetFloat64("LoginLongitude"))
	case "salesforce.loginkey":
		res = string(jdata.GetStringBytes("LoginKey"))
	case "salesforce.logintype":
		res = string(jdata.GetStringBytes("LoginType"))
	case "salesforce.loginurl":
		res = string(jdata.GetStringBytes("LoginUrl"))
	case "salesforce.operation":
		res = string(jdata.GetStringBytes("Operation"))
	case "salesforce.parentidlist":
		res = string(jdata.GetStringBytes("ParentIdList"))
	case "salesforce.parentnamelist":
		res = string(jdata.GetStringBytes("ParentNameList"))
	case "salesforce.platform":
		res = string(jdata.GetStringBytes("Platform"))
	case "salesforce.postalcode":
		res = string(jdata.GetStringBytes("PostalCode"))
	case "salesforce.previousip":
		res = string(jdata.GetStringBytes("PreviousIp"))
	case "salesforce.previousplatform":
		res = string(jdata.GetStringBytes("PreviousPlatform"))
	case "salesforce.previousscreen":
		res = string(jdata.GetStringBytes("PreviousScreen"))
	case "salesforce.previoususeragent":
		res = string(jdata.GetStringBytes("PreviousUserAgent"))
	case "salesforce.previouswindow":
		res = string(jdata.GetStringBytes("PreviousWindow"))
	case "salesforce.queriedentities":
		res = string(jdata.GetStringBytes("QueriedEntities"))
	case "salesforce.requestidentifier":
		res = string(jdata.GetStringBytes("RequestIdentifier"))
	case "salesforce.rowsprocessed":
		res = string(jdata.GetStringBytes("RowsProcessed"))
	case "salesforce.score":
		//res = string(jdata.GetStringBytes("score"))
	case "salesforce.securityeventdata":
		res = string(jdata.GetStringBytes("SecurityEventData"))
	case "salesforce.sessionlevel":
		res = string(jdata.GetStringBytes("SessionLevel"))
	case "salesforce.sessionkey":
		res = string(jdata.GetStringBytes("SessionKey"))
	case "salesforce.sourceip":
		res = string(jdata.GetStringBytes("SourceIp"))
	case "salesforce.summary":
		res = string(jdata.GetStringBytes("Summary"))
	case "salesforce.loginstatus":
		res = string(jdata.GetStringBytes("LoginStatus"))
	case "salesforce.subdivision":
		res = string(jdata.GetStringBytes("Subdivision"))
	case "salesforce.targeturl":
		res = string(jdata.GetStringBytes("TargetUrl"))
	case "salesforce.tlsprotocol":
		res = string(jdata.GetStringBytes("TlsProtocol"))
	case "salesforce.useragent":
		res = string(jdata.GetStringBytes("UserAgent"))
	case "salesforce.userid":
		res = string(jdata.GetStringBytes("UserId"))
	case "salesforce.usertype":
		res = string(jdata.GetStringBytes("UserType"))
	case "salesforce.username":
		res = string(jdata.GetStringBytes("Username"))
	case "salesforce.uri":
		res = string(jdata.GetStringBytes("Uri"))
	default:
		return false, ""
	}

	return true, res
}

// Extract a field value from an event.
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}

	return nil
}
