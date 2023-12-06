# Salesforce Plugin for Falco

## Introduction
The Salesforce Plugin for Falco ingests *Real-Time Event Monitoring Objects* from Salesforce and makes them available as fields in Falco.  You can find more about these real-time objects [here](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/platform_events_objects_monitoring.htm)

With the Salesforce fields available in Falco, you can create Falco rules to detect Salesforce threats in real-time, and alert on them through your configured notification channels.  You will find some sample Falco rules in the rules directory.
- Successful user logins and logouts (for auditing)
- Failed user logins
- Logins from foreign countries or geographies
- Adminstrators logging in as another user
- Session Hijacking detection
- Credential Stuffing detection
- Detecting permission changes on permission sets or groups
- API interaction anomaly detection

**What's the value in ingesting Salesforce events into Falco?**

Well, because Falco can perform threat detection across a number of cloud platforms in parallel, it allows you to correlate security events across multiple sources in real-time, to detect active lateral movement as it is occurring.

## Prerequisites
The plugin needs to compile with a minimum of Go version 1.16

Accessing *Real-Time Event Monitoring Objects* requires either the **Salesforce Shield** or **Salesforce Event Monitoring** add-on subscription. There may additional costs associated with streaming these objects, please contact your Salesforce representative to confirm.

The plugin is configured to ingest events from the following event streams.
- ApiAnomalyEvent
- CredentialStuffingEvent
- LoginAsEventStream
- LoginEventStream
- LogoutEventStream
- PermissionSetEvent
- SessionHijackingEvent
  
These streams must be enabled by clicking **Enable Streaming** next to them in the Event Manager. You can find information on enabling these in the *Enabling real-time events* section of this document
[here](https://developer.salesforce.com/blogs/2020/05/introduction-to-real-time-event-monitoring)

## Configuring the Falco Salesforce plugin as a Salesforce Connected App
The plugin is integrated into Salesforce as a Connected App using the Client Credentials Flow. The Client Credentials Flow method requires you to provide a ***Consumer Key***, ***Consumer Secret*** and ***SFDC Login URL*** to the plugin which it uses to authenticate.  You can find out more about using Client Credentials Flow for API authentication here: [Using the Client Credentials Flow for Easier API Authentication](https://developer.salesforce.com/blogs/2023/03/using-the-client-credentials-flow-for-easier-api-authentication)

### Creating a Connected App
The first step to getting the plugin integrated is to create a Salesforce Connected App. 

**NOTE**: the user account that you configure the Connect App to *Run As* must have the **View Real-Time Event Monitoring Data** permission

1. Follow the steps in this document to create a Salesforce Connected app with oAuth Client Credentials Flow:
[Configure a Connected App for the OAuth 2.0 Client Credentials Flow](https://help.salesforce.com/s/articleView?id=sf.ev_relay_create_connected_app.htm&type=5)
2. If you followed the steps correctly, you should now have your ***Consumer Key*** and ***Consumer Secret***. But if you some how missed the location, you can find it's location and how to rotate it here:
[Rotating Client Secret](https://help.salesforce.com/s/articleView?id=sf.connected_app_rotate_consumer_details.htm&language=en_US&type=5)

### Locating your Salesforce Login URL
You will also need to locate your SFDC login URL (My Domain) which typically uses the following format ```https://mydomain.my.salesforce.com```
You can find out more about your My Domain here: [What Is My Domain?](https://help.salesforce.com/s/articleView?id=sf.faq_domain_name_what.htm&type=5)

### Finding more info
You can find out more about Connected App and oAuth Terminology here: [Connected App and OAuth Terminology](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_terminology.htm&type=5)

## Building the Salesforce plugin
1. Download the plugin from GitHub using git
2. Change directory to falco-plugin-salesforce
3. Compile the plugin using *make*
4. Copy *libsalesforce.so* to */usr/share/falco/plugins*
5. Copy the rules to /etc/falco/rules.d/
```
git clone https://github.com/an1245/falco-plugin-salesforce
cd falco-plugin-salesforce
make
cp libsalesforce.so /usr/share/falco/plugins/
cp rules/* /etc/falco/rules.d/
```

## Configuring the plugin in Falco.yaml
Now that you have collected your ***Consumer Key***, ***Consumer Secret*** and ***SFDC Login URL***, you can provide them as values in the falco.yaml file.  
```
plugins:
  - name: salesforce
    library_path: libsalesforce.so
    init_config:
         sfdcclientid: (your consumer key)
         sfdcclientsecret: (your consumer secret)
         sfdcloginurl: (your sfdc login url)
         Debug: False
```
We recommend leaving Debug set to False unless you are trying to troubleshoot the plugin.

Now that you've got the plugin configuration done, you can enable it by adding the plugin name to the *load_plugins* configuration setting.
```
load_plugins: [salesforce]
```

## Exported Fields
There are a number of fields exported by the plugin.   

**NOTE**: Not all fields will be available for all events - please refer to the Salesforce Real-Time Event Monitoring Object documentation [here](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/platform_events_objects_monitoring.htm)

| Field Name | Type | Description |
| ----------- | ----------- |  ----------- |
| salesforce.eventtype | string | The type of SFDC event <ul><li>Login Events - LoginEvent, LogoutEvent and LoginAsEvent</li><li>Threat events - SessionHijackingEvent and CredentialStuffingEvent</li><li>Permission Events - PermissionSetEvent</li><li>API Events - ApiAnomalyEvent</li></ul>|
| salesforce.acceptlanguage | string | List of HTTP Headers that specify the natural language, such as English, that the client understands. |
| salesforce.apitype | string | The API that was used (SOAP Enterprise, SOAP Partner, None) |
| salesforce.apiversion | string | The version number of the API. |
| salesforce.application | string | The application used to access the org |
| salesforce.authmethodreference | string | What authentication method was used |
| salesforce.authserviceid | string | The authentication method used by a third-party identification provider for an OpenID Connect single sign-on protocol |
| salesforce.browser | string | The browser name and version if known |
| salesforce.ciphersuite | string | The TLS cipher suite used for the login |
| salesforce.city | string | The city where the user’s IP address is physically located |
| salesforce.clientversion | string | The version number of the login client |
| salesforce.country | string | The country where the user’s IP address is physically located |
| salesforce.countryiso | string | The ISO 3166 code for the country where the user’s IP address is physically located |
| salesforce.createdbyid | string | Who was this created by? |
| salesforce.createddate | string | What date was this created? |
| salesforce.currentip | string | The IP address of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred |
| salesforce.currentplatform | string | The platform of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred |
| salesforce.currentscreen | string | The screen of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred |
| salesforce.currentuseragent | string | The user agent of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred |
| salesforce.currentwindow | string | The browser window of the newly observed fingerprint that deviates from the previous fingerprint. The difference between the current and previous values is one indicator that a session hijacking attack has occurred |
| salesforce.delegatedusername | string | Username of the admin who is logging in as another user. |
| salesforce.delegatedorganizationid | string | Organization Id of the user who is logging in as another user |
| salesforce.evaluationtime | string | The amount of time it took to evaluate the policy in milliseconds |
| salesforce.eventdate | string | The time when the specified event occurred |
| salesforce.eventidentifier | string | The unique ID of the event |
| salesforce.eventuuid | string | A universally unique identifier (UUID) that identifies a platform event message |
| salesforce.eventsource | string | The source of the event (API, Classic etc) |
| salesforce.hasexternalusers | string | When true, external users are impacted by the operation that triggered a permission change. |
| salesforce.httpmethod | string | The HTTP method of the request |
| salesforce.impacteduserids | string | A comma-separated list of IDs of the users affected by the event |
| salesforce.loginascategory | string | Represents how the user logs in as another user |
| salesforce.logingeoid | string | The Salesforce ID of the LoginGeo object associated with the login user’s IP address |
| salesforce.loginhistoryid | string | Tracks a user session so you can correlate user activity with a particular series of API events. |
| salesforce.loginlatitude | string | The latitude where the user’s IP address is physically located |
| salesforce.loginlongitude | string | The longitude where the user’s IP address is physically located |
| salesforce.loginkey | string | The string that ties together all events in a given user’s login session |
| salesforce.logintype | string | The type of login used to access the session |
| salesforce.loginsubtype | string | The type of login flow used. See the LoginSubType field of LoginHistory in the Object Reference guide |
| salesforce.loginurl | string | The URL of the login page. |
| salesforce.operation | string | The type of operation that generated the event. For example, Query. |
| salesforce.parentidlist | string | IDs affected by the permisson change |
| salesforce.parentnamelist | string | The names of the affected permission sets or permission set groups. |
| salesforce.permissionexpirationlist | string | A comma separated list of timestamps from the PermissionSetAssignment. |
| salesforce.permissionlist | string | List of permissions |
| salesforce.permissiontype | string | The type of permission that is updated in the event |
| salesforce.platform | string | The operating system on the login machine. |
| salesforce.postalcode | string | The postal code where the user’s IP address is physically located |
| salesforce.policyid  | string | The ID of the transaction policy associated with this event |
| salesforce.policyoutcome  | string | The result of the transaction policy. |
| salesforce.previousip | string | The IP of the session that was hijacked? |
| salesforce.previousscreen | string | The screen of the session that was hijacked? |
| salesforce.previousplatform | string | The platform of the session that was hijacked? |
| salesforce.previoususeragent | string | The user agent of the session that was hijacked? |
| salesforce.previouswindow | string | The window of the session that was hijacked? |
| salesforce.queriedentities | string | The entities in the SOQL query. |
| salesforce.relatedeventidentifier | string | Represents the EventIdentifier of the related event. |
| salesforce.requestidentifier | string | The unique ID of a single transaction. |
| salesforce.rowsprocessed | string | Total row count for the current operation |
| salesforce.score | string | The score of the event.  Review developer docs for score explanation |
| salesforce.securityeventdata | string | What is the security event data of the hijacked session |
| salesforce.sessionlevel | string | Session-level security controls user access to features that support it |
| salesforce.sessionkey | string | The user’s unique session ID. |
| salesforce.sourceip | string | The source IP address of the client that is logged in |
| salesforce.summary | string | A text summary of the threat that caused this event to be created.  |
| salesforce.loginstatus | string | What was the status of the login? (success etc.) |
| salesforce.subdivision | string | The name of the subdivision where the user’s IP address is physically located |
| salesforce.targeturl | string | The URL redirected to after logging in as another user succeeds. |
| salesforce.tlsprotocol | string | The TLS protocol version used for the login |
| salesforce.useragent | string | The User-Agent header of the request |
| salesforce.usercount | string | The number of users affected by the event |
| salesforce.userid | string | The origin user’s unique ID |
| salesforce.usertype | string | The category of user license of the user |
| salesforce.username | string | The origin username in the format of user@company.com |
| salesforce.uri | string | The URI of the page that’s receiving the request. |


