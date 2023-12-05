## Setting up Falco account in Salesforce
The plugin is integrated into Salesforce as a Connected App, using a Client Credentials Flow. The client credentials flow method requires you to provide a *Consumer Key* and *Consumer Secret* to the plugin which it uses to authenticate.  

https://help.salesforce.com/s/articleView?id=sf.remoteaccess_terminology.htm&type=5

You can find out more about creating a Salesforce Connected app with oAuth here: [Configure a Connected App for the OAuth 2.0 Client Credentials Flow](https://help.salesforce.com/s/articleView?id=sf.ev_relay_create_connected_app.htm&type=5)

Please make sure you enable Client Credentials Flow in your connected app - you can find more information here: [Configure a Connected App for the OAuth 2.0 Client Credentials Flow](https://help.salesforce.com/s/articleView?id=sf.connected_app_client_credentials_setup.htm&type=5)

Once you have configured the connected app, you need to located your consumer key and secret.  You can find more on finding these values here: [Rotate the Consumer Key and Consumer Secret of a Connected App](https://help.salesforce.com/s/articleView?id=sf.connected_app_rotate_consumer_details.htm&type=) 

You can find out more about Connected App and oAuth Terminology here: [Connected App and OAuth Terminology](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_terminology.htm&type=5)
