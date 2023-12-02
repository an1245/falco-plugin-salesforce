package grpcclient

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/"
	"github.com/linkedin/goavro/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	tokenHeader    = "accesstoken"
	instanceHeader = "instanceurl"
	tenantHeader   = "tenantid"
)

type PubSubClient struct {
	accessToken string
	instanceURL string

	userID string
	orgID  string

	conn         *grpc.ClientConn
	pubSubClient proto.PubSubClient

	schemaCache map[string]*goavro.Codec
}

// Closes the underlying connection to the gRPC server
func (c *PubSubClient) Close() {
	c.conn.Close()
}

// Makes a call to the OAuth server to fetch credentials. Credentials are stored as part of the PubSubClient object so that they can be
// referenced later in other methods
func (c *PubSubClient) Authenticate() error {
	resp, err := oauth.Login()
	if err != nil {
		return err
	}

	c.accessToken = resp.AccessToken
	c.instanceURL = resp.InstanceURL

	return nil
}

// Makes a call to the OAuth server to fetch user info. User info is stored as part of the PubSubClient object so that it can be referenced
// later in other methods
func (c *PubSubClient) FetchUserInfo() error {
	resp, err := oauth.UserInfo(c.accessToken)
	if err != nil {
		return err
	}

	c.userID = resp.UserID
	c.orgID = resp.OrganizationID

	return nil
}

// Wrapper function around the GetTopic RPC. This will add the OAuth credentials and make a call to fetch data about a specific topic
func (c *PubSubClient) GetTopic() (*proto.TopicInfo, error) {
	var trailer metadata.MD

	req := &proto.TopicRequest{
		TopicName: common.TopicName,
	}

	ctx, cancelFn := context.WithTimeout(c.getAuthContext(), common.GRPCCallTimeout)
	defer cancelFn()

	resp, err := c.pubSubClient.GetTopic(ctx, req, grpc.Trailer(&trailer))
	printTrailer(trailer)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Wrapper function around the GetSchema RPC. This will add the OAuth credentials and make a call to fetch data about a specific schema
func (c *PubSubClient) GetSchema(schemaId string) (*proto.SchemaInfo, error) {
	var trailer metadata.MD

	req := &proto.SchemaRequest{
		SchemaId: schemaId,
	}

	ctx, cancelFn := context.WithTimeout(c.getAuthContext(), common.GRPCCallTimeout)
	defer cancelFn()

	resp, err := c.pubSubClient.GetSchema(ctx, req, grpc.Trailer(&trailer))
	printTrailer(trailer)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Wrapper function around the Subscribe RPC. This will add the OAuth credentials and create a separate streaming client that will be used to
// fetch data from the topic. This method will continuously consume messages unless an error occurs; if an error does occur then this method will
// return the last successfully consumed ReplayId as well as the error message. If no messages were successfully consumed then this method will return
// the same ReplayId that it originally received as a parameter
func (c *PubSubClient) Subscribe(replayPreset proto.ReplayPreset, replayId []byte) ([]byte, error) {
	ctx, cancelFn := context.WithCancel(c.getAuthContext())
	defer cancelFn()

	subscribeClient, err := c.pubSubClient.Subscribe(ctx)
	if err != nil {
		return replayId, err
	}
	defer subscribeClient.CloseSend()

	initialFetchRequest := &proto.FetchRequest{
		TopicName:    common.TopicName,
		ReplayPreset: replayPreset,
		NumRequested: common.Appetite,
	}
	if replayPreset == proto.ReplayPreset_CUSTOM && replayId != nil {
		initialFetchRequest.ReplayId = replayId
	}

	err = subscribeClient.Send(initialFetchRequest)
	// If the Send call returns an EOF error then print a log message but do not return immediately. Instead, let the Recv call (below) determine
	// if there's a more specific error that can be returned
	// See the SendMsg description at https://pkg.go.dev/google.golang.org/grpc#ClientStream
	if err == io.EOF {
		log.Printf("WARNING - EOF error returned from initial Send call, proceeding anyway")
	} else if err != nil {
		return replayId, err
	}

	requestedEvents := initialFetchRequest.NumRequested

	// NOTE: the replayId should be stored in a persistent data store rather than being stored in a variable
	curReplayId := replayId
	for {
		log.Printf("Waiting for events...")
		resp, err := subscribeClient.Recv()
		if err == io.EOF {
			printTrailer(subscribeClient.Trailer())
			return curReplayId, fmt.Errorf("stream closed")
		} else if err != nil {
			printTrailer(subscribeClient.Trailer())
			return curReplayId, err
		}

		for _, event := range resp.Events {
			codec, err := c.fetchCodec(event.GetEvent().GetSchemaId())
			if err != nil {
				return curReplayId, err
			}

			parsed, _, err := codec.NativeFromBinary(event.GetEvent().GetPayload())
			if err != nil {
				return curReplayId, err
			}

			body, ok := parsed.(map[string]interface{})
			if !ok {
				return curReplayId, fmt.Errorf("error casting parsed event: %v", body)
			}

			// Again, this should be stored in a persistent external datastore instead of a variable
			curReplayId = event.GetReplayId()

			log.Printf("event body: %+v\n", body)
			log.Printf("event body: %+v\n", body["Application"])
			testApp := body["Application"]
			log.Printf("test: %v+v\n",testApp)

			// decrement our counter to keep track of how many events have been requested but not yet processed. If we're below our configured
			// batch size then proactively request more events to stay ahead of the processor
			requestedEvents--
			if requestedEvents < common.Appetite {
				log.Printf("Sending next FetchRequest...")
				fetchRequest := &proto.FetchRequest{
					TopicName:    common.TopicName,
					NumRequested: common.Appetite,
				}

				err = subscribeClient.Send(fetchRequest)
				// If the Send call returns an EOF error then print a log message but do not return immediately. Instead, let the Recv call (above) determine
				// if there's a more specific error that can be returned
				// See the SendMsg description at https://pkg.go.dev/google.golang.org/grpc#ClientStream
				if err == io.EOF {
					log.Printf("WARNING - EOF error returned from subsequent Send call, proceeding anyway")
				} else if err != nil {
					return curReplayId, err
				}

				requestedEvents += fetchRequest.NumRequested
			}
		}
	}
}

// Unexported helper function to retrieve the cached codec from the PubSubClient's schema cache. If the schema ID is not found in the cache
// then a GetSchema call is made and the corresponding codec is cached for future use
func (c *PubSubClient) fetchCodec(schemaId string) (*goavro.Codec, error) {
	codec, ok := c.schemaCache[schemaId]
	if ok {
		log.Printf("Fetched cached codec...")
		return codec, nil
	}

	log.Printf("Making GetSchema request for uncached schema...")
	schema, err := c.GetSchema(schemaId)
	if err != nil {
		return nil, err
	}

	log.Printf("Creating codec from uncached schema...")
	codec, err = goavro.NewCodec(schema.GetSchemaJson())
	if err != nil {
		return nil, err
	}

	c.schemaCache[schemaId] = codec

	return codec, nil
}


// Returns a new context with the necessary authentication parameters for the gRPC server
func (c *PubSubClient) getAuthContext() context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		tokenHeader, c.accessToken,
		instanceHeader, c.instanceURL,
		tenantHeader, c.orgID,
	))
}

// Creates a new connection to the gRPC server and returns the wrapper struct
func NewGRPCClient() (*PubSubClient, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithBlock(),
	}

	if common.GRPCEndpoint == "localhost:7011" {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		certs := getCerts()
		creds := credentials.NewClientTLSFromCert(certs, "")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), common.GRPCDialTimeout)
	defer cancelFn()

	conn, err := grpc.DialContext(ctx, common.GRPCEndpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	return &PubSubClient{
		conn:         conn,
		pubSubClient: proto.NewPubSubClient(conn),
		schemaCache:  make(map[string]*goavro.Codec),
	}, nil
}

// Fetches system certs and returns them if possible. If unable to fetch system certs then an empty cert pool is returned instead
func getCerts() *x509.CertPool {
	if certs, err := x509.SystemCertPool(); err == nil {
		return certs
	}

	return x509.NewCertPool()
}

// Helper function to display trailers on the console in a more readable format
func printTrailer(trailer metadata.MD) {
	if len(trailer) == 0 {
		log.Printf("no trailers returned")
		return
	}

	log.Printf("beginning of trailers")
	for key, val := range trailer {
		log.Printf("[trailer] = %s, [value] = %s", key, val)
	}
	log.Printf("end of trailers")
}
