** Create a developer account and interface with API **
- reference: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/quickstart_dev_org.htm
- create developer account: https://developer.salesforce.com/signup
- salesforce pub/sub API -
---- Python code sample - https://developer.salesforce.com/docs/platform/pub-sub-api/guide/qs-python-quick-start.html
---- Go code sample - https://github.com/developerforce/pub-sub-api/tree/main/go

**Execute SOQL Query**
- reference - query objects: https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_loginhistory.htm
- reference - query via API : https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_query.htm
- example: curl https://MyDomainName.my.salesforce.com/services/data/v59.0/query/?q=SELECT+name+from+Account -H "Authorization: Bearer token"
- SOQL query for Login History:
1. SELECT UserId, LoginTime from LoginHistory;
2. SELECT UserId, LoginTime from LoginHistory WHERE LoginTime > 2010-09-20T22:16:30.000Z;

TODO:
- Login Failures
- Login IPs
- Login GEO


** Creating Webhooks in Salesforce **
https://www.youtube.com/watch?v=1X0tugN8-Gs
