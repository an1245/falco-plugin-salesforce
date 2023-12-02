// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package salesforce

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)


func (p *Plugin) initInstance(oCtx *PluginInstance) error {
	oCtx.whSrv = nil

	// Exract the user parameters
	var terr error
	oCtx.ghOauth.token, terr = GetGithubToken(p.config.SecretsDir)
	if terr != nil {
		return terr
	}

	// Create the token-authenticated http client that we will use to talk to github through
	// its API
	oCtx.ghOauth.ctx = context.Background()
	oCtx.ghOauth.ts = oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: oCtx.ghOauth.token},
	)
	oCtx.ghOauth.tc = oauth2.NewClient(oCtx.ghOauth.ctx, oCtx.ghOauth.ts)
	oCtx.ghClient = github.NewClient(oCtx.ghOauth.tc)

	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}

	// if l is used as second argument, list all repositories for the authenticated user
	repos, gerr := listRepos(oCtx)
	if gerr != nil {
		return nil, gerr
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("the given token cannot access any repository on github")
	}

	var res []sdk.OpenParam
	for _, repo := range repos {
		if repo.perm_Admin && !repo.archived {
			res = append(res, sdk.OpenParam{
				Value: repo.fullName,
				Desc:  "",
			})
		}
	}

	res = append(res, sdk.OpenParam{
		Value: "*",
		Desc:  "Attaches to every repository accessible with the given token",
	})

	return res, nil
}

// Open an event stream and return an open plugin instance.
func (p *Plugin) Open(params string) (source.Instance, error) {
	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}
	oCtx.whSecret, _ = password.Generate(32, 5, 5, false, false)

	var selected_repos []string

	// if l is used as second argument, list all repositories for the authenticated user
	if params == "*" {
		// Fetch the list of the user's repos
		repos, gerr := listRepos(oCtx)
		if gerr != nil {
			return nil, gerr
		}
		if len(repos) == 0 {
			return nil, fmt.Errorf("the given token cannot access any repository on github")
		}

		for _, repo := range repos {
			rname := strings.Trim(repo.fullName, "\"")
			if repo.perm_Admin && !repo.archived {
				selected_repos = append(selected_repos, rname)
			}
		}
	} else {
		pa := strings.Split(params, ",")
		for _, rawRepo := range pa {
			// clean up the string in case the use put spaces among them
			repo := strings.Trim(rawRepo, " ")
			repo = strings.Trim(repo, "\t")
			selected_repos = append(selected_repos, repo)
		}
	}

	// Compile the regular expressions used to find secrests in commits
	err = compileRegexes(oCtx)
	if err != nil {
		fmt.Println(err)
	}

	// Compile the regular expressions used to find miners in github actions
	err = compileMinerRegexes(oCtx)
	if err != nil {
		fmt.Println(err)
	}

	// Create the channel that we'll use to collect the messages from the webserver
	oCtx.whSrvChan = make(chan []byte, 128)

	// Launch the webhook web server
	go server(p, oCtx)

	// Install the webhook in all of the selected repositories
	oCtx.whURL = p.config.WebsocketServerURL

	for _, repoName := range selected_repos {
		log.Printf("Installing webhook in github repo %s\n", repoName)
		rnComps := strings.Split(repoName, "/")
		if len(rnComps) != 2 {
			return nil, fmt.Errorf("[%s] invalid repository name %s. Expected format: owner/name, e.g. falcosecurity/falco", PluginName, repoName)
		}

		loginName := rnComps[0] // *repo.Owner.Login
		repoName := rnComps[1]  // *repo.Name

		hooks, _, gerr := oCtx.ghClient.Repositories.ListHooks(oCtx.ghOauth.ctx, loginName, repoName, nil)
		if gerr != nil {
			return nil, gerr
		}

		for _, hook := range hooks {
			if hook.Config["url"] == oCtx.whURL {
				// Hook already installed for this repo. Delete it and start clean.
				_, gerr := oCtx.ghClient.Repositories.DeleteHook(oCtx.ghOauth.ctx, loginName, repoName, hook.GetID())
				if gerr != nil {
					return nil, gerr
				}

				break
			}
		}

		hname := "web" // Note: this needs to be "web" or Github will throw an error
		active := true

		hookInfo := github.Hook{
			Name:   &hname,
			URL:    &oCtx.whURL,
			Events: []string{"*"},
			Active: &active,
			Config: map[string]interface{}{
				"content_type": "form",
				"secret":       oCtx.whSecret,
				"insecure_ssl": 0,
				"url":          oCtx.whURL}}

		hook, _, gerr := oCtx.ghClient.Repositories.CreateHook(oCtx.ghOauth.ctx, loginName, repoName, &hookInfo)
		_ = hook
		if gerr != nil {
			return nil, gerr
		}

		// Remember this webhook so we can delete it on close
		nh := githubHookInfo{
			owner: loginName,
			repo:  repoName,
			id:    hook.GetID(),
		}

		oCtx.installedHooks = append(oCtx.installedHooks, nh)
	}

	return oCtx, nil
}

// Closing the event stream and deinitialize the open plugin instance.
func (o *PluginInstance) Close() {
	// Shut down the webhook webserver
	if o.whSrv != nil {
		err := o.whSrv.Shutdown(context.Background())
		if err != nil {
			log.Printf("github webhook shutdown failed: %s", err)
		}
	}

	// Remove all the webhhoks that we installed in open()
	for _, hook := range o.installedHooks {
		log.Printf("deleting webhook from %s/%s\n", hook.owner, hook.repo)
		o.ghClient.Repositories.DeleteHook(o.ghOauth.ctx, hook.owner, hook.repo, hook.id)
	}
}

// Produce and return a new batch of events.
func (o *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Casting to our plugin type
	pCtx := pState.(*Plugin)

	// Batching is not supported for now, so we only write the first entry of the batch
	evt := evts.Get(0)
	writer := evt.Writer()

	// Receive the event from the webserver channel with a 1 sec timeout
	var data []byte
	afterCh := time.After(1 * time.Second)
	select {
	case data = <-o.whSrvChan:
	case <-afterCh:
		pCtx.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// If the buffer starts with an 'E', it means it contains an error
	if data[0] == 'E' {
		return 0, fmt.Errorf("%s", (data[2:]))
	}

	// Write data inside the event
	written, err := writer.Write(data)
	if err != nil {
		return 0, err
	}
	if written < len(data) {
		return 0, fmt.Errorf("github message too long: %d, max %d supported", len(data), written)
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

// Provide a string representation for an event.
func (p *Plugin) String(evt sdk.EventReader) (string, error) {
	var line string
	var err error

	data, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}

	p.jdata, err = p.jparser.ParseBytes(data)
	if err != nil {
		return "", fmt.Errorf("<invalid JSON: %s>" + err.Error())
	}

	line = "github "
	line += string(p.jdata.GetStringBytes("webhook_type"))
	user := p.jdata.Get("sender", "login").GetStringBytes()
	if user != nil {
		line += (" user:" + string(user))
	}

	repo := p.jdata.Get("repository", "html_url").GetStringBytes()
	if repo != nil {
		line += (" repo:" + string(repo))
	}

	action := p.jdata.Get("action").GetStringBytes()
	if action != nil {
		line += (" action:" + string(action))
	}

	return line, nil
}
