package grpcclient

import (
        "context"
        "crypto/x509"
        "fmt"
        "io"
        "log"
        "sync"
        "time"

        "github.com/developerforce/pub-sub-api/go/common"
        "github.com/developerforce/pub-sub-api/go/oauth"
        "github.com/developerforce/pub-sub-api/go/proto"
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
                        LoginEventIns := StringMapToLoginEvent(parsed.(map[string]interface{}))
                        log.Printf("City: %s", LoginEventIns.City)

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

// Wrapper function around the Publish RPC. This will add the OAuth credentials and produce a single hardcoded event to the specified topic.
func (c *PubSubClient) Publish(schema *proto.SchemaInfo) error {
        log.Printf("Creating codec from schema...")
        codec, err := goavro.NewCodec(schema.SchemaJson)
        if err != nil {
                return err
        }

        sampleEvent := map[string]interface{}{
                "CreatedDate":        time.Now().Unix(),
                "CreatedById":        c.userID,
                "Mileage__c":         goavro.Union("double", 95443.0),
                "Cost__c":            goavro.Union("double", 99.40),
                "WorkDescription__c": goavro.Union("string", "Replaced front brakes"),
        }

        payload, err := codec.BinaryFromNative(nil, sampleEvent)
        if err != nil {
                return err
        }

        var trailer metadata.MD

        req := &proto.PublishRequest{
                TopicName: common.TopicName,
                Events: []*proto.ProducerEvent{
                        {
                                SchemaId: schema.GetSchemaId(),
                                Payload:  payload,
                        },
                },
        }

        ctx, cancelFn := context.WithTimeout(c.getAuthContext(), common.GRPCCallTimeout)
        defer cancelFn()

        pubResp, err := c.pubSubClient.Publish(ctx, req, grpc.Trailer(&trailer))
        printTrailer(trailer)

        if err != nil {
                return err
        }

        result := pubResp.GetResults()
        if result == nil {
                return fmt.Errorf("nil result returned when publishing to %s", common.TopicName)
        }

        if err := result[0].GetError(); err != nil {
                return fmt.Errorf(result[0].GetError().GetMsg())
        }

        return nil
}

// Wrapper function around the PublishStream RPC. This will add the OAuth credentials and produce an event to the topic every five seconds
func (c *PubSubClient) PublishStream(schema *proto.SchemaInfo) error {
        log.Printf("Creating codec from schema...")
        codec, err := goavro.NewCodec(schema.SchemaJson)
        if err != nil {
                return err
        }

        ctx, cancelFn := context.WithCancel(c.getAuthContext())
        defer cancelFn()

        publishClient, err := c.pubSubClient.PublishStream(ctx)
        if err != nil {
                return err
        }

        sampleEvent := map[string]interface{}{
                "CreatedDate":        time.Now().Unix(),
                "CreatedById":        c.userID,
                "Mileage__c":         goavro.Union("double", 95443.0),
                "Cost__c":            goavro.Union("double", 99.40),
                "WorkDescription__c": goavro.Union("string", "Replaced front brakes"),
        }

        payload, err := codec.BinaryFromNative(nil, sampleEvent)
        if err != nil {
                return err
        }

        publishRequest := &proto.PublishRequest{
                TopicName: common.TopicName,
                Events: []*proto.ProducerEvent{
                        {
                                SchemaId: schema.GetSchemaId(),
                                Payload:  payload,
                        },
                },
        }

        err = publishClient.Send(publishRequest)
        // If the Send call returns an EOF error then print a log message but do not return immediately. Instead, let the Recv call (below) determine
        // if there's a more specific error that can be returned
        // See the SendMsg description at https://pkg.go.dev/google.golang.org/grpc#ClientStream
        if err == io.EOF {
                log.Printf("WARNING - EOF error returned from initial Send call, proceeding anyway")
        } else if err != nil {
                return err
        }

        log.Printf("Entering event loop...")

        var resErrMutex sync.Mutex
        var resErr error

        shutdownGoroutine := func(err error) {
                cancelFn()

                resErrMutex.Lock()
                defer resErrMutex.Unlock()

                // only capture the first error returned
                if resErr == nil {
                        resErr = err
                }
        }

        wg := sync.WaitGroup{}
        wg.Add(2)

        // sender goroutine. This goroutine will attempt to publish a new event every 5 seconds. This goroutine will run until one of the following
        // conditions is met:
        // 1. the receiver goroutine returned an error and exited
        // 2. this goroutine encounters an error while publishing
        go func() {
                defer wg.Done()
                defer publishClient.CloseSend()

                for {
                        select {
                        case <-ctx.Done():
                                return
                        default:
                                time.Sleep(5 * time.Second)

                                log.Printf("Sending next PublishRequest...")
                                sampleEvent["CreatedDate"] = time.Now().Unix()

                                payload, sendErr := codec.BinaryFromNative(nil, sampleEvent)
                                if sendErr != nil {
                                        shutdownGoroutine(sendErr)
                                        return
                                }

                                publishRequest := &proto.PublishRequest{
                                        TopicName: common.TopicName,
                                        Events: []*proto.ProducerEvent{
                                                {
                                                        SchemaId: schema.GetSchemaId(),
                                                        Payload:  payload,
                                                },
                                        },
                                }

                                sendErr = publishClient.Send(publishRequest)
                                // if we encounter an EOF error from the Send method then exit this goroutine without canceling the context or recording the error.
                                // The Recv method called in the receiver goroutine may return a more specific error explaining why the stream was closed.
                                // See the SendMsg description at https://pkg.go.dev/google.golang.org/grpc#ClientStream
                                if sendErr == io.EOF {
                                        log.Printf("WARNING - EOF error returned from subsequent Send call, proceeding anyway")
                                        return
                                } else if sendErr != nil {
                                        shutdownGoroutine(sendErr)
                                        return
                                }
                        }
                }
        }()

        // receiver goroutine. This goroutine will attempt to receive the PublishStream responses as they are sent back from the Pub/Sub API. This
        // goroutine will run until one of the following conditions is met:
        // 1. the sender goroutine returned an error and exited
        // 2. this goroutine either encounters an error while receiving or the PublishStream response indicates an error occurred while publishing
        go func() {
                defer wg.Done()

                for {
                        select {
                        case <-ctx.Done():
                                return
                        default:
                                pubResp, recvErr := publishClient.Recv()
                                if recvErr == io.EOF {
                                        printTrailer(publishClient.Trailer())
                                        shutdownGoroutine(fmt.Errorf("stream closed"))
                                        return
                                } else if recvErr != nil {
                                        printTrailer(publishClient.Trailer())
                                        shutdownGoroutine(recvErr)
                                        return
                                }

                                results := pubResp.GetResults()
                                if results == nil {
                                        shutdownGoroutine(fmt.Errorf("nil results received"))
                                        return
                                }

                                for _, res := range results {
                                        if res.GetError() != nil {
                                                shutdownGoroutine(fmt.Errorf(res.GetError().GetMsg()))
                                                return
                                        }
                                }

                                log.Printf("successfully published event")
                        }
                }
        }()

        wg.Wait()

        return resErr
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

// User holds information about a user.
type LoginEvent struct {
        ApiType string
        ApiVersion string
        Application string
        AuthMethodReference string
        AuthServiceId string
        Browser string
        CipherSuite string
        City string
        ClientVersion string
        Country string
        CountryIso string
        CreatedById string
        CreatedDate string
        EvaluationTime float64
        EventDate float64
        EventIdentifier string
        HttpMethod string
        LoginGeoId string
        LoginHistoryId string
        LoginKey string
        LoginLatitude float64
        LoginLongitude float64
        LoginSubType string
        LoginType string
        LoginUrl string
        Platform string
        PolicyId string
        PolicyOutcome string
        PostalCode string
        RelatedEventIdentifier string
        SessionKey string
        SessionLevel string
        SourceIp string
        Status string
        Subdivision string
        TlsProtocol string
        UserId string
        UserType string
        Username string
}

func StringMapToLoginEvent(data map[string]interface{}) *LoginEvent {

        ind := &LoginEvent{}
        ind.City = "Auckland"
        for k, v := range data {
                switch k {
                case "ApiType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ApiType = b.(string)
                                }
                        }
                case "ApiVersion":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.ApiVersion = b.(string)
                                }
                        }
                case "Application":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Application = b.(string)
                                }
                        }

                case "AuthMethodReference":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.AuthMethodReference = b.(string)
                                }
                        }

                case "AuthServiceId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.AuthServiceId = b.(string)
                                }
                        }

                case "Browser":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Browser = b.(string)
                                }
                        }

                case "CipherSuite":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CipherSuite = b.(string)
                                }
                        }

                case "City":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.City = b.(string)
                                }
                        }

                case "ClientVersion":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.ClientVersion = b.(string)
                                }
                        }

                case "Country":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Country = b.(string)
                                }
                        }

                case "CountryIso":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CountryIso = b.(string)
                                }
                        }

                case "CreatedById":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CreatedById = b.(string)
                                }
                        }

                case "CreatedDate":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CreatedDate = b.(string)
                                }
                        }

                case "EvaluationTime":
                        if value, ok := v.(map[int64]interface{}); ok {
                                for _, b := range value {
                                        ind.EvaluationTime = b.(float64)
                                }
                        }

                case "EventDate":
                        if value, ok := v.(map[int64]interface{}); ok {
                                for _, b := range value {
                                        ind.EventDate = b.(float64)
                                }
                        }
                case "EventIdentifier":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.EventIdentifier = b.(string)
                                }
                        }
                case "HttpMethod":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.HttpMethod = b.(string)
                                }
                        }
                case "LoginGeoId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginGeoId = b.(string)
                                }
                        }
                case "LoginHistoryId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.LoginHistoryId = b.(string)
                                }
                        }
                case "LoginKey":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginKey = b.(string)
                                }
                        }
                case "LoginLatitude":
                        if value, ok := v.(map[int64]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginLatitude = b.(float64)
                                }
                        }
                case "LoginLongitude":
                        if value, ok := v.(map[int64]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginLongitude = b.(float64)
                                }
                        }
                case "LoginSubType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginSubType = b.(string)
                                }
                        }
                case "LoginType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginType = b.(string)
                                }
                        }
                case "LoginUrl":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginUrl = b.(string)
                                }
                        }
                case "Platform":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Platform = b.(string)
                                }
                        }
                case "PolicyId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PolicyId = b.(string)
                                }
                        }
                case "PolicyOutcome":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PolicyOutcome = b.(string)
                                }
                        }
                case "PostalCode":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PostalCode = b.(string)
                                }
                        }
                case "RelatedEventIdentifier":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.RelatedEventIdentifier = b.(string)
                                }
                        }
                case "SessionKey":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.SessionKey = b.(string)
                                }
                        }
                case "SessionLevel":
                        if value, ok := v.(map[string]interface{}); ok {
                               for _, b := range value {
                                         ind.SessionLevel = b.(string)
                                }
                        }
                case "Status":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Status = b.(string)
                                }
                        }
                case "Subdivision":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.Subdivision = b.(string)
                                }
                        }
                case "TlsProtocol":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.TlsProtocol = b.(string)
                                }
                        }
                case "UserId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserId = b.(string)
                                }
                        }
                case "UserType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserType = b.(string)
                                }
                        }
                case "Username":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Username = b.(string)
                                }
                        }
                }
        }
        return ind

}
