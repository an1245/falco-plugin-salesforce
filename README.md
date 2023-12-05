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
There are a number of fields exported by the plugin.   **NOTE**: Not all fields will be available for all events - please refer to the Salesforce Real-Time Event Monitoring Object documentation [here](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/platform_events_objects_monitoring.htm)

| Field Name | Type | Description |
| ----------- | ----------- |  ----------- |
| salesforce.eventtype | string | What type of SFDC event was this? (example. LoginEvent)

