package grpcclient

import (
        "context"
        "crypto/x509"
        "fmt"
        "io"
        "log"
        "encoding/json"
	"reflect"
        "errors"

	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/oauth"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/proto"
	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/common"
        
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

	Debug bool
}

// Closes the underlying connection to the gRPC server
func (c *PubSubClient) Close() {
        c.conn.Close()
}

// Makes a call to the OAuth server to fetch credentials. Credentials are stored as part of the PubSubClient object so that they can be
// referenced later in other methods
func (c *PubSubClient) Authenticate(clientid string, clientsecret string, sfdcloginurl string) error {
        resp, err := oauth.Login(clientid, clientsecret,sfdcloginurl )
        if err != nil {
                return err
        }

        c.accessToken = resp.AccessToken
        c.instanceURL = resp.InstanceURL

        return nil
}

// Makes a call to the OAuth server to fetch user info. User info is stored as part of the PubSubClient object so that it can be referenced
// later in other methods
func (c *PubSubClient) FetchUserInfo(sfdcloginurl string) error {
        resp, err := oauth.UserInfo(c.accessToken, sfdcloginurl )
        if err != nil {
                return err
        }

        c.userID = resp.UserID
        c.orgID = resp.OrganizationID

        return nil
}

// Wrapper function around the GetTopic RPC. This will add the OAuth credentials and make a call to fetch data about a specific topic
func (c *PubSubClient) GetTopic(topicName string) (*proto.TopicInfo, error) {
        var trailer metadata.MD

        req := &proto.TopicRequest{
                TopicName: topicName,
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
                return nil, fmt.Errorf("Salesforce Plugin ERROR: Couldn't Get Schema - %v", err)
		 
        }

        return resp, nil
}

// Wrapper function around the Subscribe RPC. This will add the OAuth credentials and create a separate streaming client that will be used to
// fetch data from the topic. This method will continuously consume messages unless an error occurs; if an error does occur then this method will
// return the last successfully consumed ReplayId as well as the error message. If no messages were successfully consumed then this method will return
// the same ReplayId that it originally received as a parameter
func (c *PubSubClient) Subscribe(replayPreset proto.ReplayPreset, replayId []byte, channel chan []byte, topicName string, eventType string) ([]byte, error) {
        ctx, cancelFn := context.WithCancel(c.getAuthContext())
        defer cancelFn()

        subscribeClient, err := c.pubSubClient.Subscribe(ctx)
        if err != nil {
                return replayId, err
        }
        defer subscribeClient.CloseSend()

        initialFetchRequest := &proto.FetchRequest{
                TopicName:    topicName,
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
                log.Printf("Salesforce Plugin: WARNING - EOF error returned from initial Send call, proceeding anyway")
        } else if err != nil {
                return replayId, err
        }

        requestedEvents := initialFetchRequest.NumRequested

        // NOTE: the replayId should be stored in a persistent data store rather than being stored in a variable
        curReplayId := replayId
        for {
		
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
                                return curReplayId, fmt.Errorf("Salesforce Plugin ERROR: Error casting parsed event: %v", body)
                        }

			if (c.Debug) {
				log.Printf("Salesforce Plugin: AVRO Response Body: %+v\n", body)
			}
			
                        // Again, this should be stored in a persistent external datastore instead of a variable
                        curReplayId = event.GetReplayId()
                        SFDCEventIns, err := StringMapToSFDCEvent(parsed.(map[string]interface{}), eventType, c.Debug)
                        if err != nil {
                                fmt.Printf("Salesforce Plugin: WARNING - failed to translate AVRO field - %v", err)
                        }
                        
                       SFDCEventJSON, err := json.Marshal(SFDCEventIns)
                        if err != nil {
                               return nil, err
                        }

			if (c.Debug) {
				log.Printf("Salesforce Plugin: Passing this JSON back to NextBatch (source.go)")
				fmt.Println(string(SFDCEventJSON))
			}

			channel <- SFDCEventJSON
		}

                        // decrement our counter to keep track of how many events have been requested but not yet processed. If we're below our configured
                        // batch size then proactively request more events to stay ahead of the processor
                        requestedEvents--
                        if requestedEvents < common.Appetite {
                                fetchRequest := &proto.FetchRequest{
                                        TopicName:    topicName,
                                        NumRequested: common.Appetite,
                                }

                                err = subscribeClient.Send(fetchRequest)
                                // If the Send call returns an EOF error then print a log message but do not return immediately. Instead, let the Recv call (above) determine
                                // if there's a more specific error that can be returned
                                // See the SendMsg description at https://pkg.go.dev/google.golang.org/grpc#ClientStream
                                if err == io.EOF {
                                        log.Printf("Salesforce Plugin: WARNING - EOF error returned from subsequent Send call, proceeding anyway")
                                } else if err != nil {
                                        return curReplayId, err
                                }

                                requestedEvents += fetchRequest.NumRequested
                        }
                }
        
}

// Unexported helper function to retrieve the cached codec from the PubSubClient's schema cache. If the schema ID is not found in the cache
// then a GetSchema call is made and the corresponding codec is cached for future use
func (c *PubSubClient) fetchCodec(schemaId string) (*goavro.Codec, error) {
        codec, ok := c.schemaCache[schemaId]
        if ok {
                if (c.Debug) {
			log.Printf("Salesforce Plugin: Fetched cached codec...")
		}
                return codec, nil
        }

        if (c.Debug) {
		log.Printf("Salesforce Plugin: Making GetSchema request for uncached schema...")
	}
        schema, err := c.GetSchema(schemaId)
        if err != nil {
                return nil, err
        }
	if (c.Debug) {
       	 	log.Printf("Salesforce Plugin: Creating codec from uncached schema...")
	}
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
func NewGRPCClient(isDebug bool) (*PubSubClient, error) {
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
		Debug: isDebug,
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
	                return
	        }
	
	        log.Printf("Salesforce Plugin: GRPC returned trailers - beginning..")
	        for key, val := range trailer {
	                log.Printf("[trailer] = %s, [value] = %s", key, val)
	        }
	        log.Printf("Salesforce Plugin: GRPC returned trailers - end..")
       
}

// User holds information about a user.
type SFDCEvent struct {
        EventType string
	AcceptLanguage string
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
        CreatedDate int64
	CurrentIp string
	CurrentPlatform string
	CurrentScreen string
	CurrentUserAgent string
	CurrentWindow string
	DelegatedOrganizationId string
	DelegatedUsername string
        EvaluationTime float64
        EventDate int64
        EventIdentifier string
	EventUuid string
	EventSource string
        HasExternalUsers bool
	HttpMethod string
	ImpactedUserIds string
        LoginAsCategory string
	LoginGeoId string
        LoginHistoryId string
        LoginKey string
        LoginLatitude float64
        LoginLongitude float64
        LoginSubType string
        LoginType string
        LoginUrl string
	Operation string
	ParentIdList string
	ParentNameList string
	PermissionExpirationList string
	PermissionList string
	PermissionType string
        Platform string
        PolicyId string
        PolicyOutcome string
        PostalCode string
	PreviousIp string
	PreviousPlatform string
	PreviousScreen string
	PreviousUserAgent string
	PreviousWindow string
	QueriedEntities string
        RelatedEventIdentifier string
	RequestIdentifier string
	ReplayId string
	RowsProcessed int64
        Score int64
	SecurityEventData string
	SessionKey string
        SessionLevel string
        SourceIp string
	Summary string
        LoginStatus string
        Subdivision string
	TargetUrl string
        TlsProtocol string
        UserAgent string
	UserCount string
	UserId string
        UserType string
        Username string
	Uri string
}

func StringMapToSFDCEvent(data map[string]interface{}, eventType string, Debug bool) (*SFDCEvent, error) {

        ind := &SFDCEvent{}
        ind.EventType = eventType
	if (Debug) {
		log.Printf("Salesforce Plugin: Processing %s event", eventType)
	}

        errorSlice := []string{}

        for k, v := range data {
		if (Debug) {
			log.Printf("Salesforce Plugin: Processing field %s", k)
		}
                switch k {
	     	case "AcceptLanguage":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        if _,ok := b.(string); ok {
                                                ind.AcceptLanguage = b.(string)
                                        } else { errorSlice = append(errorSlice,"AcceptLanguage") }
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"AcceptLanguage") }
		case "ApiType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ApiType = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ApiType") }
                case "ApiVersion":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.ApiVersion = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ApiVersion") }
                case "Application":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Application = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Application") }

                case "AuthMethodReference":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.AuthMethodReference = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"AuthMethodReference") }

                case "AuthServiceId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.AuthServiceId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"AuthServiceId") }

                case "Browser":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Browser = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Browser") }

                case "CipherSuite":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CipherSuite = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CipherSuite") }

                case "City":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.City = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"City") }

                case "ClientVersion":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.ClientVersion = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ClientVersion") }

                case "Country":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Country = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Country") }

                case "CountryIso":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CountryIso = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CountryIso") }

                case "CreatedById":
                        if value, ok := v.(string); ok {                    
                                ind.CreatedById = value
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CreatedById") }

                case "CreatedDate":
                        if value, ok := v.(int64); ok {
                                ind.CreatedDate = value
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CreatedDate") }
		 case "CurrentIp":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CurrentIp = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CurrentIp") }
		case "CurrentPlatform":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CurrentPlatform = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CurrentPlatform") }
		case "CurrentScreen":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CurrentScreen = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CurrentScreen") }
		case "CurrentUserAgent":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CurrentUserAgent = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CurrentUserAgent") }
		case "CurrentWindow":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.CurrentWindow = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"CurrentWindow") }
		 case "DelegatedOrganizationId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.DelegatedOrganizationId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"DelegatedOrganizationId") }

		 case "DelegatedUsername":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.DelegatedUsername = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"DelegatedUsername") }

                case "EvaluationTime":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.EvaluationTime = b.(float64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"EvaluationTime") }

                case "EventDate":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.EventDate = b.(int64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"EventDate") }
                
		case "EventIdentifier":
			if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.EventIdentifier = b.(string)
                                }
                        } else {
			
				vtype := reflect.TypeOf(v).Kind()
				if vtype == reflect.String {
					ind.EventIdentifier = v.(string)
					
				}
			}
			
		case "EventSource":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.EventSource = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"EventSource") }
		case "EventUuid":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.EventUuid = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"EventUuid") }
                case "HasExternalUsers":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.HasExternalUsers = b.(bool)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"HasExternalUsers") }
		case "HttpMethod":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.HttpMethod = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"HttpMethod") }
		case "ImpactedUserIds":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ImpactedUserIds = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ImpactedUserIds") }
                case "LoginAsCategory":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginAsCategory = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginAsCategory") }
		case "LoginGeoId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginGeoId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginGeoId") }
                case "LoginHistoryId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.LoginHistoryId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginHistoryId") }
                case "LoginKey":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginKey = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginKey") }
                case "LoginLatitude":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginLatitude = b.(float64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginLatitude") }
                case "LoginLongitude":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginLongitude = b.(float64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginLongitude") }
                case "LoginSubType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginSubType = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginSubType") }
                case "LoginType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginType = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginType") }
                case "LoginUrl":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginUrl = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"LoginUrl") }
		case "Operation":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Operation = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Operation") }
		case "ParentIdList":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ParentIdList = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ParentIdList") }
		case "ParentNameList":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ParentNameList = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ParentNameList") }
		case "PermissionExpirationList":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PermissionExpirationList = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PermissionExpirationList") }
		case "PermissionList":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PermissionList = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PermissionList") }
		case "PermissionType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PermissionType = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PermissionType") }
                case "Platform":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Platform = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Platform") }
                case "PolicyId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PolicyId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PolicyId") }
                case "PolicyOutcome":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PolicyOutcome = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PolicyOutcome") }
                case "PostalCode":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PostalCode = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PostalCode") }
		case "PreviousIp":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PreviousIp = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PreviousIp") }
		case "PreviousPlatform":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PreviousPlatform = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PreviousPlatform") }
		case "PreviousScreen":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PreviousScreen = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PreviousScreen") }
		case "PreviousUserAgent":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PreviousUserAgent = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PreviousUserAgent") }
		case "PreviousWindow":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.PreviousWindow = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"PreviousWindow") }
		case "QueriedEntities":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.QueriedEntities = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"QueriedEntities") }
                case "ReplayId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.ReplayId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"ReplayId") }
		 case "RequestIdentifier":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.RequestIdentifier = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"RequestIdentifier") }
		case "RelatedEventIdentifier":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.RelatedEventIdentifier = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"RelatedEventIdentifier") }
		case "RowsProcessed":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.RowsProcessed = b.(int64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"RowsProcessed") }
		case "Score":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Score = b.(int64)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Score") }
		case "SecurityEventData":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.SecurityEventData = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"SecurityEventData") }
                case "SessionKey":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.SessionKey = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"SessionKey") }
                case "SessionLevel":
                        if value, ok := v.(map[string]interface{}); ok {
                               for _, b := range value {
                                         ind.SessionLevel = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"SessionLevel") }
		case "SourceIp":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.SourceIp = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"SourceIp") }
                case "Status":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.LoginStatus = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Status") }
                case "Subdivision":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.Subdivision = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Subdivision") }
		 case "Summary":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                         ind.Summary = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Summary") }
		 case "TargetUrl":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.TargetUrl = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"TargetUrl") }
                case "TlsProtocol":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.TlsProtocol = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"TlsProtocol") }
                case "UserAgent":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserAgent = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"UserAgent") }
		case "UserCount":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserCount = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"UserCount") }
		case "UserId":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserId = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"UserId") }
                case "UserType":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.UserType = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"UserType") }
                case "Username":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Username = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Username") }
		 case "Uri":
                        if value, ok := v.(map[string]interface{}); ok {
                                for _, b := range value {
                                        ind.Uri = b.(string)
                                }
                        } else if v == nil { } else { errorSlice = append(errorSlice,"Uri") }
                }

                
        }

        if (len(errorSlice) > 0) {
                errorstring := ""
                for _, element := range errorSlice {
                        errorstring += fmt.Sprintf(" %s", element)
                }

                error1 := errors.New(errorstring)

                return ind, error1
        } else {
                return ind, nil
        }

   

}
