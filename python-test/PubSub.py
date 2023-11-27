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
        sef.topic_name = '/events/'

      def subscribe

  
                
        
