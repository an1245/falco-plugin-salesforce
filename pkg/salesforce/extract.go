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
		{Type: "string", Name: "salesforce.eventtype", Display: "Event Type", Desc: "The type of SFDC event (example. LoginEvent)"},
		{Type: "string", Name: "salesforce.acceptlanguage", Display: "Accept Language", Desc: "List of HTTP Headers that specify the natural language, such as English, that the client understands."},
		{Type: "string", Name: "salesforce.apitype", Display: "API Type", Desc: "The API that was used (SOAP Enterprise, SOAP Partner, None)"},
		{Type: "string", Name: "salesforce.apiversion", Display: "API Version", Desc: "The version number of the API."},
		{Type: "string", Name: "salesforce.application", Display: "Login Application", Desc: "The application used to access the org"},
		{Type: "string", Name: "salesforce.authmethodreference", Display: "Auth Method", Desc: "What authentication method was used"},
		{Type: "string", Name: "salesforce.authserviceid", Display: "Auth Service ID", Desc: "The authentication method used by a third-party identification provider for an OpenID Connect single sign-on protocol"},
		{Type: "string", Name: "salesforce.browser", Display: "Browser Type", Desc: "The browser name and version if known"},
		{Type: "string", Name: "salesforce.ciphersuite", Display: "Cipher Suite", Desc: "The TLS cipher suite used for the login"},
		{Type: "string", Name: "salesforce.city", Display: "City", Desc: "The city where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.clientversion", Display: "Client Version", Desc: "The version number of the login client"},
		{Type: "string", Name: "salesforce.country", Display: "Country", Desc: "The country where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.countryiso", Display: "Country ISO", Desc: "The ISO 3166 code for the country where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.createdbyid", Display: "Created By", Desc: "Who was this created by?"},
		{Type: "string", Name: "salesforce.createddate", Display: "Created Date", Desc: "What date was this created?"},
		{Type: "string", Name: "salesforce.currentip", Display: "Current Hijacked IP", Desc: "The IP address of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred"},
		{Type: "string", Name: "salesforce.currentplatform", Display: "Current Hijacked Platform", Desc: "The platform of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred"},
		{Type: "string", Name: "salesforce.currentscreen", Display: "Current Hijacked Screen", Desc: "The screen of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred"},
		{Type: "string", Name: "salesforce.currentuseragent", Display: "Current Hijacked UserAgent", Desc: "The user agent of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred"},
		{Type: "string", Name: "salesforce.currentwindow", Display: "Current Hijacked Window", Desc: "The browser window of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred"},
		{Type: "string", Name: "salesforce.delegatedusername", Display: "Delegated Username", Desc: "Username of the admin who is logging in as another user."},
		{Type: "string", Name: "salesforce.delegatedorganizationid", Display: "Delegated Organisation", Desc: "Organization Id of the user who is logging in as another user"},
		{Type: "string", Name: "salesforce.evaluationtime", Display: "Evaluation Time", Desc: "The amount of time it took to evaluate the policy in milliseconds"},
		{Type: "string", Name: "salesforce.eventdate", Display: "Event Date", Desc: "The time when the specified event occurred"},
		{Type: "string", Name: "salesforce.eventidentifier", Display: "Event Identifier", Desc: "The unique ID of the event"},
		{Type: "string", Name: "salesforce.eventuuid", Display: "Event UUID", Desc: "A universally unique identifier (UUID) that identifies a platform event message"},
		{Type: "string", Name: "salesforce.eventsource", Display: "Event Source", Desc: "The source of the event (API, Classic etc)"},
		{Type: "string", Name: "salesforce.hasexternalusers", Display: "Has External Users", Desc: "When true, external users are impacted by the operation that triggered a permission change."},
		{Type: "string", Name: "salesforce.httpmethod", Display: "HTTP Method", Desc: "The HTTP method of the request"},
		{Type: "string", Name: "salesforce.impacteduserids", Display: "External Users Impacted", Desc: "A comma-separated list of IDs of the users affected by the event"},
		{Type: "string", Name: "salesforce.loginascategory", Display: "Login As Cateory", Desc: "Represents how the user logs in as another user"},
		{Type: "string", Name: "salesforce.logingeoid", Display: "Login Geo ID", Desc: "The Salesforce ID of the LoginGeo object associated with the login user’s IP address"},
		{Type: "string", Name: "salesforce.loginhistoryid", Display: "Login History ID", Desc: "Tracks a user session so you can correlate user activity with a particular series of API events."},
		{Type: "string", Name: "salesforce.loginlatitude", Display: "Login Latitude", Desc: "The latitude where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.loginlongitude", Display: "Login Longitude", Desc: "The longitude where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.loginkey", Display: "Login Key", Desc: "The string that ties together all events in a given user’s login session"},
		{Type: "string", Name: "salesforce.logintype", Display: "Login Type", Desc: "The type of login used to access the session"},
		{Type: "string", Name: "salesforce.loginsubtype", Display: "Login Sub Type", Desc: "The type of login flow used. See the LoginSubType field of LoginHistory in the Object Reference guide"},
		{Type: "string", Name: "salesforce.loginurl", Display: "Login URL", Desc: "The URL of the login page."},
		{Type: "string", Name: "salesforce.operation", Display: "Operation", Desc: "The type of operation that generated the event. For example, Query."},
		{Type: "string", Name: "salesforce.parentidlist", Display: "Parent ID List", Desc: "IDs affected by the permisson change"},
		{Type: "string", Name: "salesforce.parentnamelist", Display: "Permission Sets affected", Desc: "The names of the affected permission sets or permission set groups."},
		{Type: "string", Name: "salesforce.permissionexpirationlist", Display: "List of expired permissions", Desc: "A comma separated list of timestamps from the PermissionSetAssignment."},
		{Type: "string", Name: "salesforce.permissionlist", Display: "List of permissions", Desc: "List of permissions"},
		{Type: "string", Name: "salesforce.permissiontype", Display: "Type of permissions", Desc: "The type of permission that is updated in the event"},
		{Type: "string", Name: "salesforce.platform", Display: "Login Platform", Desc: "The operating system on the login machine."},
		{Type: "string", Name: "salesforce.postalcode", Display: "Login Postal Code", Desc: "The postal code where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.policyid ", Display: "Policy ID", Desc: "The ID of the transaction policy associated with this event"},
		{Type: "string", Name: "salesforce.policyoutcome ", Display: "Policy Outcome", Desc: "The result of the transaction policy."},
		{Type: "string", Name: "salesforce.previousip", Display: "Previous Hijacked IP", Desc: "The IP of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previousscreen", Display: "Previous Hijacked Screen", Desc: "The screen of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previousplatform", Display: "Previous Hijacked Platform ", Desc: "The platform of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previoususeragent", Display: "Previous Hijacked User Agent", Desc: "The user agent of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.previouswindow", Display: "Previous Hijacked Window", Desc: "The window of the session that was hijacked?"},
		{Type: "string", Name: "salesforce.queriedentities", Display: "Queried Entities", Desc: "The entities in the SOQL query."},
		{Type: "string", Name: "salesforce.relatedeventidentifier", Display: "Related Event ID", Desc: "Represents the EventIdentifier of the related event."},
		{Type: "string", Name: "salesforce.requestidentifier", Display: "API transaction ID", Desc: "The unique ID of a single transaction."},
		{Type: "string", Name: "salesforce.rowsprocessed", Display: "Rows Proessed in transaction", Desc: "Total row count for the current operation"},
		{Type: "string", Name: "salesforce.score", Display: "Security Event Score", Desc: "The score of the event.  Review developer docs for score explanation"},
		{Type: "string", Name: "salesforce.securityeventdata", Display: "Hijacking Security Event Data", Desc: "What is the security event data of the hijacked session"},
		{Type: "string", Name: "salesforce.sessionlevel", Display: "Session Level", Desc: "Session-level security controls user access to features that support it"},
		{Type: "string", Name: "salesforce.sessionkey", Display: "Session Key", Desc: "The user’s unique session ID."},
		{Type: "string", Name: "salesforce.sourceip", Display: "Source IP", Desc: "The source IP address of the client that is logged in"},
		{Type: "string", Name: "salesforce.summary", Display: "Text Summary", Desc: "A text summary of the threat that caused this event to be created. "},
		{Type: "string", Name: "salesforce.loginstatus", Display: "Login Status", Desc: "What was the status of the login? (success etc.)"},
		{Type: "string", Name: "salesforce.subdivision", Display: "Login Subdivision", Desc: "The name of the subdivision where the user’s IP address is physically located"},
		{Type: "string", Name: "salesforce.targeturl", Display: "Target URL", Desc: "The URL redirected to after logging in as another user succeeds."},
		{Type: "string", Name: "salesforce.tlsprotocol", Display: "TLS Protocol", Desc: "The TLS protocol version used for the login"},
		{Type: "string", Name: "salesforce.useragent", Display: "User Agent", Desc: "The User-Agent header of the request"},
		{Type: "string", Name: "salesforce.usercount", Display: "User Count", Desc: "The number of users affected by the event"},
		{Type: "string", Name: "salesforce.userid", Display: "User ID", Desc: "The origin user’s unique ID"},
		{Type: "string", Name: "salesforce.usertype", Display: "User Type", Desc: "The category of user license of the user"},
		{Type: "string", Name: "salesforce.username", Display: "Username", Desc: "The origin username in the format of user@company.com"},
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
	case "salesforce.apitype":
		res = string(jdata.GetStringBytes("ApiType"))
	case "salesforce.apiversion":
		res = string(jdata.GetStringBytes("ApiVersion"))
	case "salesforce.application":
		res = string(jdata.GetStringBytes("Application"))
	case "salesforce.authmethodreference":
		res = string(jdata.GetStringBytes("AuthMethodReference"))
	case "salesforce.authserviceid":
		res = string(jdata.GetStringBytes("AuthServiceId"))
	case "salesforce.browser":
		res = string(jdata.GetStringBytes("Browser"))
	case "salesforce.ciphersuite":
		res = string(jdata.GetStringBytes("CipherSuite"))
	case "salesforce.city":
		res = string(jdata.GetStringBytes("City"))
	case "salesforce.clientversion":
		res = string(jdata.GetStringBytes("ClientVersion"))
	case "salesforce.country":
		res = string(jdata.GetStringBytes("Country"))
	case "salesforce.countryiso":
		res = string(jdata.GetStringBytes("CountryIso"))
	case "salesforce.createdbyid":
		res = string(jdata.GetStringBytes("CreatedById"))
	case "salesforce.createddate":
		res = string(jdata.GetStringBytes("CreatedDate"))
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
		res = fmt.Sprintf("%f",jdata.GetStringBytes("HasExternalUsers"))
	case "salesforce.httpmethod":
		res = string(jdata.GetStringBytes("HttpMethod"))
	case "salesforce.impacteduserids":
		res = string(jdata.GetStringBytes("ImpactedUserIds"))
	case "salesforce.loginascategory":
		res = string(jdata.GetStringBytes("LoginAsCategory"))
	case "salesforce.logingeoid":
		res = string(jdata.GetStringBytes("LoginGeoId"))
	case "salesforce.loginhistoryid":
		res = string(jdata.GetStringBytes("LoginHistoryId"))
	case "salesforce.loginlatitude":
		res = fmt.Sprintf("%f",jdata.GetStringBytes("LoginLatitude"))
	case "salesforce.loginlongitude":
		res = fmt.Sprintf("%f",jdata.GetStringBytes("LoginLongitude"))
	case "salesforce.loginkey":
		res = string(jdata.GetStringBytes("LoginKey"))
	case "salesforce.logintype":
		res = string(jdata.GetStringBytes("LoginType"))
	case "salesforce.loginsubtype":
		res = string(jdata.GetStringBytes("LoginSubType"))
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
	case "salesforce.policyid":
		res = string(jdata.GetStringBytes("PolicyId"))
	case "salesforce.policyoutcome":
		res = string(jdata.GetStringBytes("PolicyOutcome"))
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
	case "salesforce.relatedeventidentifier":
		res = string(jdata.GetStringBytes("RelatedEventIdentifier"))
	case "salesforce.requestidentifier":
		res = string(jdata.GetStringBytes("RequestIdentifier"))
	case "salesforce.rowsprocessed":
		res = string(jdata.GetStringBytes("RowsProcessed"))
	case "salesforce.score":
		res = fmt.Sprintf("%f",jdata.GetStringBytes("Score"))
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
