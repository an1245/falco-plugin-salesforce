## Create a developer account and interface with API 
- reference: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/quickstart_dev_org.htm
- create developer account: https://developer.salesforce.com/signup
- create connected app with oAuth - https://help.salesforce.com/s/articleView?id=sf.ev_relay_create_connected_app.htm&type=5
- oAuth Endpoints - https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_endpoints.htm&type=5
- Enable username/password flow - https://help.salesforce.com/s/articleView?id=release-notes.rn_security_username-password_flow_blocked_by_default.htm&release=244&type=5
- Client Credential Flow - https://help.salesforce.com/s/articleView?id=sf.connected_app_client_credentials_setup.htm&type=5
- Client Credential Flow - 

## Salesforce pub/sub API 
- Python code sample - https://developer.salesforce.com/docs/platform/pub-sub-api/guide/qs-python-quick-start.html
- Python demo video - https://www.youtube.com/watch?v=8HmrDN9OUCg
- Go code sample - https://github.com/developerforce/pub-sub-api/tree/main/go
- Creating Pub/Sub topics - https://www.googlecloudcommunity.com/gc/Integration-Services/salesforce-to-gcp-real-time-Events/m-p/597003#M288
- AVRO decoding to struct - https://github.com/linkedin/goavro/blob/master/examples/nested/main.go

## Platform Events 
- reference - query objects: https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_loginhistory.htm
- Platform events - login - https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_loginevent.htm
- SFDC Event Manager: https://sysdig6-dev-ed.develop.lightning.force.com/lightning/setup/EventManager/home
- Monitoring Event Monitor - https://help.salesforce.com/s/articleView?id=sf.event_monitoring_monitor_events_with_event_manager.htm&type=5
- Need to set the event manager (Login Event) and set it to streaming https://sysdig6-dev-ed.develop.lightning.force.com/lightning/setup/EventManager/home

## API - Execute SOQL Query 
- SOQL query for Login History:
- example: curl https://MyDomainName.my.salesforce.com/services/data/v59.0/query/?q=SELECT+name+from+Account -H "Authorization: Bearer token"
1. SELECT UserId, LoginTime from LoginHistory;
2. SELECT UserId, LoginTime from LoginHistory WHERE LoginTime > 2010-09-20T22:16:30.000Z;
3. SELECT Application, Browser, EventDate, EventIdentifier, LoginUrl, UserId FROM LoginEvent WHERE EventDate<Yesterday AND Status=’Success’
- reference - query via API : https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_query.htm

## TODO
- Login Failures
- Login IPs
- Login GEO
