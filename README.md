# Salesforce Plugin for Falco

## Introduction


## Configuring the Falco Salesforce plugin as a Salesforce Connected App
The plugin is integrated into Salesforce as a Connected App using the Client Credentials Flow. The Client Credentials Flow method requires you to provide a *Consumer Key*, *Consumer Secret* and *SFDC Login URL* to the plugin which it uses to authenticate.  You can find out more about using Client Credentials Flow for API authentication here: [Using the Client Credentials Flow for Easier API Authentication](https://developer.salesforce.com/blogs/2023/03/using-the-client-credentials-flow-for-easier-api-authentication)

### Creating a Connected App
The first step to getting the plugin integrated is to create a Salesforce Connected App.
1. This document talks about creating a Salesforce Connected app with oAuth Client Credentials Flow:
[Configure a Connected App for the OAuth 2.0 Client Credentials Flow](https://help.salesforce.com/s/articleView?id=sf.ev_relay_create_connected_app.htm&type=5)
2. You also need to make sure you have enabled Client Credentials Flow in your connected app - you can find more information here:
[Configure a Connected App for the OAuth 2.0 Client Credentials Flow](https://help.salesforce.com/s/articleView?id=sf.connected_app_client_credentials_setup.htm&type=5)

### Locating your Consumer Key and Secret
Once you have configured the connected app, you need to locate your consumer key and secret.  You can find more on finding these values here: [Rotate the Consumer Key and Consumer Secret of a Connected App](https://help.salesforce.com/s/articleView?id=sf.connected_app_rotate_consumer_details.htm&type=) 

### Locating your Salesforce Login URL
You will also need to locate your SFDC login URL (My Domain) which typically uses the following format *https://mydomain.my.salesforce.com* - you can find out more about finding this info here: [What Is My Domain?](https://help.salesforce.com/s/articleView?id=sf.faq_domain_name_what.htm&type=5)

### Configuring the plugin in Falco.yaml
Now that you have this information, you can provide them as values in the falco.yaml file.
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
And don't forget to enable the plugin by setting the following setting
```
load_plugins: [salesforce]
```

### Finding more info
You can find out more about Connected App and oAuth Terminology here: [Connected App and OAuth Terminology](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_terminology.htm&type=5)
