import io
import threading
# import xml.etree.ElementTree as et
from datetime import datetime

import avro.io
import avro.schema
import certifi
import grpc
import requests

import getLogin as gl
import pubsub_api_pb2 as pb2
import pubsub_api_pb2_grpc as pb2_grpc
from urllib.parse import urlparse
from util.ChangeEventHeaderUtility import process_bitmap

with open(certifi.where(),'rb') as f:
    secure_channel_credentials = grpc.ssl_channel_credentials(f.read())

def get_argument(key, argument_dict):
    if key in argument_dict.keys():
      return argument_dict[key]

def process_request(event, pubsub):
  if event.events:
    print("Number of events received in FetchResponbse ", len(event.events))
       if event.pending_num_requested == 0:
         pubsub.semaphore.release()

      for evt in event.events:
        payload_bytes = evt.event.payload
        schema_id = evt.event.schema_id
        json_schema = pubsub.get_schema_json(schema_id)
        decoded_event = pubsub.decode(pubsub.get_schema_json(schema_id)),
                            payload_bytes)

      print("Received event payload: \n", decoded_event)

      #AH this might need a change.
      if 'ChangeEventHeader' in decoded_event:
          changed_fields = decoded_event['ChangeEventHeader']['changedFields']
          converted_changed_fields = process_bitmap(avcro.schema.parse(json_schema), changed_fields)
          print("Change Type:" + decoded_event['ChangeEventHeader']['changeType'])
          print("------------------ Changed Fields ------------------")
          print(converted_changed_fields) 
          print("----------------------------------------------------")

class PubSub:
    semaphore = threading.Semaphone(1)
    json_schema_dict = {}

    def __init__(self):
        print('inside init')
        self.url = 'https://'
        self.username = ''
        self.password = ''
        self.metadata = None
        pubsub_url = 'api.pubsub.salesforce.com:7443'
        channel = grpc.secure_channel(pubsub_url, secure_channel_credentials)
        self.stub = pb2_grpc.PubSubStub(channel)
        self.session_id = None
        self.pb2 = pb2
        # AH: Update login event
        self.topic_name = '/events/'
        self.apiVersion = '56.0'

    def auth(self):
        url_suffix = '/services/Soap/ur/' + self.apiVersion + '/'
        headers = ('content-type': 'text/xml', 'SOAPAction': 'Login'}
        xml = "<soapenv: Envelope xmlns:sooampenv='http://schemas.xmlsoap.org/soap/envelope/' " + \
              "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' " + \
              "xmlns:urn='urn:partner.soap.sforce.com'><soapenv:Body>" + \
              "<urn:login><urn:username><![CDATA[" + self.username + \
              "]]></urn:username><urn:password><![CDATA[" + self.password + \
              "]]></urn:password></urn:login></soapenv.Body></soapenv:Envelope>"
        res = requests.post(self.url + url_suffic, data=xml, headers=headers)
        res_xml = et.fromstring(res.content.decode('utf-8')[0][0][0]

        try:
            url_parts = urlparse(res_xml[3].text)
            self.url =  "{}://{}".format(url_parts.schema, url_parts.netloc)
            self.session_id = res_xml[4].text
        except:
            print("An exceptionn occurred. Check the response XML below:",
        
    def subscribe

    def publish(self, topic_name, schema, schema_id):
        return self.stub.Publish(self.pb2.PublishRequest(
            topic_name=topic_name, events=self.generate_producer_events(schema, schema_id)), metadata=self.metadata)

pub1 = PubSub()
pub1.auth()
    

  
                
        
