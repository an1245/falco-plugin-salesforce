package common

import (
	"time"

	"github.com/an1245/falco-plugin-salesforce/pkg/salesforce/sfdcclient/proto"
)

var (
	// topic and subscription-related variables
	TopicName           = "/event/LoginEventStream"
	LoginTopic	    = "/event/LoginEventStream"
	LogoutTopic	    = "/event/LogoutEventStream"
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
