package common

import (
	"time"

	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/proto"
)

var (
	// topic and subscription-related variables
	LoginTopic	    = "/event/LoginEventStream"
	LoginTopicEventType = "LoginEvent"
	LogoutTopic	    = "/event/LogoutEventStream"
	LogoutTopicEventType = "LogoutEvent"
	LoginAsTopic 	     = "/event/LoginAsEventStream"
	LoginAsTopicEventType = "LoginAsEvent"
	SessionHijackingTopic = "/event/SessionHijackingEvent"
	SessionHijackingEventType = "SessionHijackingEvent"
	CredentialStuffingTopic = "/event/CredentialStuffingEvent"
	CredentialStuffingEventType = "CredentialStuffingEvent"
	PermissionSetEventTopic = "/event/PermissionSetEvent"
	PermissionSetEventType = "PermissionSetEvent"
	ApiAnomalyEventTopic = "/event/ApiAnomalyEvent"
	ApiAnomalyEventType = "ApiAnomalyEvent"
	
	ReplayPreset        = proto.ReplayPreset_LATEST
	ReplayId     []byte = nil
	Appetite     int32  = 5

	// gRPC server variables
	GRPCEndpoint    = "api.pubsub.salesforce.com:7443"
	GRPCDialTimeout = 5 * time.Second
	GRPCCallTimeout = 5 * time.Second

	// OAuth header variables
	GrantType    = "client_credentials"

	OAuthDialTimeout = 5 * time.Second
)
