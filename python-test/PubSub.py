"""
PubSub.py

This file defines the class `PubSub`, which contains common functionality for
both publisher and subscriber clients. 
"""

import io
import threading
import xml.etree.ElementTree as et
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

with open(certifi.where(), 'rb') as f:
    secure_channel_credentials = grpc.ssl_channel_credentials(f.read())


def get_argument(key, argument_dict):
    if key in argument_dict.keys():
        return argument_dict[key]
def process_request(event, pubsub):

    if event.events:
        print("Number of events received in FetchResponse: ", len(event.events))
        # If all requested events are delivered, release the semaphore
        # so that a new FetchRequest gets sent by `PubSub.fetch_req_stream()`.
        if event.pending_num_requested == 0:
            pubsub.semaphore.release()

        for evt in event.events:
            payload_bytes = evt.event.payload
            schema_id = evt.event.schema_id
            json_schema = pubsub.get_schema_json(schema_id)
            decoded_event = pubsub.decode(pubsub.get_schema_json(schema_id),
                                    payload_bytes)

            print("Received event payload: \n", decoded_event)
            #  A change event contains the ChangeEventHeader field. Check if received event is a change event. 
            if 'ChangeEventHeader' in decoded_event:
                # Decode the bitmap fields contained within the ChangeEventHeader. For example, decode the 'changedFields' field.
                # An example to process bitmap in 'changedFields'
                changed_fields = decoded_event['ChangeEventHeader']['changedFields']
                converted_changed_fields = process_bitmap(avro.schema.parse(json_schema), changed_fields)
                print("Change Type: " + decoded_event['ChangeEventHeader']['changeType'])
                print("=========== Changed Fields =============")
                print(converted_changed_fields)
                print("=========================================")
                # Do not process updates made by the SalesforceListener app to the opportunity record delivery date 
                if decoded_event['ChangeEventHeader']['changeOrigin'].find('client=SalesforceListener') != -1:
                    print("Skipping change event because it is an update to the delivery date by SalesforceListener.")
                    return



class PubSub:
    """
    Class with helpers to use the Salesforce Pub/Sub API.
    """
    semaphore = threading.Semaphore(1)
    json_schema_dict = {}

    def __init__(self):
        print('inside init')
        self.url = 'https://login.salesforce.com'
        self.username = gl.username
        self.password = gl.password
        self.metadata = None
        pubsub_url = 'api.pubsub.salesforce.com:7443'
        channel = grpc.secure_channel(pubsub_url, secure_channel_credentials)
        self.stub = pb2_grpc.PubSubStub(channel)
        self.session_id = None
        self.pb2 = pb2
        self.topic_name = '/data/AccountChangeEvent'

        self.apiVersion = '55.0'


    def auth(self):
        """
        Sends a login request to the Salesforce SOAP API to retrieve a session
        token. The session token is bundled with other identifying information
        to create a tuple of metadata headers, which are needed for every RPC
        call.
        """
        url_suffix = '/services/Soap/u/' + self.apiVersion + '/'
        headers = {'content-type': 'text/xml', 'SOAPAction': 'Login'}
        xml = "<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/' " + \
              "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' " + \
              "xmlns:urn='urn:partner.soap.sforce.com'><soapenv:Body>" + \
              "<urn:login><urn:username><![CDATA[" + self.username + \
              "]]></urn:username><urn:password><![CDATA[" + self.password + \
              "]]></urn:password></urn:login></soapenv:Body></soapenv:Envelope>"
        res = requests.post(self.url + url_suffix, data=xml, headers=headers)
        res_xml = et.fromstring(res.content.decode('utf-8'))[0][0][0]

        try:
            url_parts = urlparse(res_xml[3].text)
            self.url = "{}://{}".format(url_parts.scheme, url_parts.netloc)
            self.session_id = res_xml[4].text
        except IndexError:
            print("An exception occurred. Check the response XML below:", 
            res.__dict__)

        # Get org ID from UserInfo
        uinfo = res_xml[6]
        # Org ID
        self.tenant_id = uinfo[8].text;

        # Set metadata headers
        self.metadata = (('accesstoken', self.session_id),
                         ('instanceurl', self.url),
                         ('tenantid', self.tenant_id))

    def make_fetch_request(self, topic, replay_type, replay_id, num_requested):
        """
        Creates a FetchRequest per the proto file.
        """
        replay_preset = None
        match replay_type:
            case "LATEST":
                replay_preset = pb2.ReplayPreset.LATEST
            case "EARLIEST":
                replay_preset = pb2.ReplayPreset.EARLIEST
            case "CUSTOM":
                replay_preset = pb2.ReplayPreset.CUSTOM
            case _:
                raise ValueError('Invalid Replay Type ' + replay_type)
        
        print(replay_preset)
        print(topic)
        print(num_requested)
        return pb2.FetchRequest(
            topic_name=topic,
            replay_preset=replay_preset,
            num_requested=num_requested)

    def fetch_req_stream(self, topic, replay_type, replay_id, num_requested):
        """
        Returns a FetchRequest stream for the Subscribe RPC.
        """
        while True:
            self.semaphore.acquire()
            yield self.make_fetch_request(topic, 'LATEST', replay_id, num_requested)

    def encode(self, schema, payload):
        """
        Uses Avro and the event schema to encode a payload. The `encode()` and
        `decode()` methods are helper functions to serialize and deserialize
        the payloads of events that clients will publish and receive using
        Avro. If you develop an implementation with a language other than
        Python, you will need to find an Avro library in that language that
        helps you encode and decode with Avro. When publishing an event, the
        plaintext payload needs to be Avro-encoded with the event schema for
        the API to accept it. When receiving an event, the Avro-encoded payload
        needs to be Avro-decoded with the event schema for you to read it in
        plaintext. 
        """
        schema = avro.schema.parse(schema)
        buf = io.BytesIO()
        encoder = avro.io.BinaryEncoder(buf)
        writer = avro.io.DatumWriter(schema)
        writer.write(payload, encoder)
        return buf.getvalue()

    def decode(self, schema, payload):
        """
        Uses Avro and the event schema to decode a serialized payload. The
        `encode()` and `decode()` methods are helper functions to serialize and
        deserialize the payloads of events that clients will publish and
        receive using Avro. If you develop an implementation with a language
        other than Python, you will need to find an Avro library in that
        language that helps you encode and decode with Avro. When publishing an
        event, the plaintext payload needs to be Avro-encoded with the event
        schema for the API to accept it. When receiving an event, the
        Avro-encoded payload needs to be Avro-decoded with the event schema for
        you to read it in plaintext.
        """
        schema = avro.schema.parse(schema)
        buf = io.BytesIO(payload)
        decoder = avro.io.BinaryDecoder(buf)
        reader = avro.io.DatumReader(schema)
        ret = reader.read(decoder)
        return ret

    def get_topic(self, topic_name):
        return self.stub.GetTopic(pb2.TopicRequest(topic_name=topic_name),
                                  metadata=self.metadata)

    def get_schema_json(self, schema_id):
        """
        Uses GetSchema RPC to retrieve schema given a schema ID.
        """
        # If the schema is not found in the dictionary, get the schema and store it in the dictionary
        if schema_id not in self.json_schema_dict or self.json_schema_dict[schema_id]==None:
            res = self.stub.GetSchema(pb2.SchemaRequest(schema_id=schema_id), metadata=self.metadata)
            self.json_schema_dict[schema_id] = res.schema_json

        return self.json_schema_dict[schema_id]

    def generate_producer_events(self, schema, schema_id):
        """
        Encodes the data to be sent in the event and creates a ProducerEvent per
        the proto file.
        """
        payload = {
            "CreatedDate": int(datetime.now().timestamp()),
            "CreatedById": '0052v00000ckJrhAAE',  # Your user ID
            "Price__c": 96000
        }
        req = {
            "schema_id": schema_id,
            "payload": self.encode(schema, payload)
        }
        return [req]

    def subscribe(self, topic, replay_type, replay_id, num_requested, callback):
        """
        Calls the Subscribe RPC defined in the proto file and accepts a
        client-defined callback to handle any events that are returned by the
        API. It uses a semaphore to prevent the Python client from closing the
        connection prematurely (this is due to the way Python's GRPC library is
        designed and may not be necessary for other languages--Java, for
        example, does not need this). 
        """
        print('metadata-->',self.metadata)
        print('topic_name--',self.topic_name)
        sub_stream = self.stub.Subscribe(self.fetch_req_stream(topic, replay_type, replay_id, num_requested), metadata=self.metadata)
        print("> Subscribed to", self.topic_name)
        print('sub_Steam-->',sub_stream)
        for event in sub_stream:
            callback(event, self)


    def publish(self, topic_name, schema, schema_id):
        """
        Publishes events to the specified Platform Event topic.
        """
        return self.stub.Publish(self.pb2.PublishRequest(
            topic_name=topic_name,
            events=self.generate_producer_events(schema,schema_id)),metadata=self.metadata)



pub1 = PubSub()
pub1.auth()
#Code to Subscribe to the channel
#pub1.subscribe('/data/AccountChangeEvent',None,None,1,process_request)

#Code to Publish to the channel
mypubtopic = '/event/Bitcoin_Price__e'
schemaid = pub1.get_topic(mypubtopic).schema_id
schema = pub1.get_schema_json(schemaid)
pub1.publish(mypubtopic,schema,schemaid)


