package pulltabs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"

	"appengine"
	"appengine/urlfetch"
)

type notifier struct {
	Label      string
	Message    string
	Secret     string
	SlackURL   string
	StatusTmpl *template.Template
}

type pullRequestPost struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		HTMLURL string `json:"html_url"`
		State   string `jsong:"state"`
		Title   string `json:"title"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
	} `json:"pull_request"`
	Label struct {
		Name string `json:"name"`
	} `json:"label"`
}

type Attachment struct {
	Fallback  string `json:"fallback"`
	Color     string `json:"color"`
	Pretext   string `json:"pretext"`
	Title     string `json:"title"`
	TitleLink string `json:"title_link"`
	Text      string `json:"text"`
}

type slackMessage struct {
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments"`
}

func (s notifier) output(pr pullRequestPost) (*bytes.Buffer, error) {
	m := slackMessage{
		Text: s.Message,
		Attachments: []Attachment{
			Attachment{
				Text:      "Review me please",
				Color:     "good",
				Fallback:  s.Message,
				Pretext:   fmt.Sprintf("Pull request tagged with %s", s.Label),
				Title:     pr.PullRequest.Title,
				TitleLink: pr.PullRequest.HTMLURL,
			},
		},
	}
	b := bytes.NewBuffer(make([]byte, 2048))
	if err := json.NewEncoder(b).Encode(&m); err != nil {
		return nil, err
	}
	return b, nil
}

func (s notifier) validHMAC(req *http.Request, body []byte) bool {
	if s.Secret == "" {
		return true
	}

	sig := req.Header.Get("X-Hub-Signature")
	if sig == "" {
		return false
	}

	mac := hmac.New(sha1.New, []byte(s.Secret))
	mac.Write(body)
	expectedSig := "sha1=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(sig))
}

func (s notifier) status(c appengine.Context, w http.ResponseWriter, req *http.Request) {
	ctx := struct {
		Instance string
		Label    string
	}{
		Instance: appengine.InstanceID(),
		Label:    s.Label,
	}
	w.Header().Set("CONTENT-TYPE", "text/html; charset=UTF-8")
	w.Header().Set("CACHE-CONTROL", "max-age=0, no-cache")
	if req.Method != "HEAD" {
		s.StatusTmpl.Execute(w, ctx)
	}
	c.Infof("Successfully served status page for request %s", appengine.RequestID(c))
}

func (s notifier) payload(c appengine.Context, w http.ResponseWriter, req *http.Request) {
	reqID := appengine.RequestID(c)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Could not read request", http.StatusInternalServerError)
		return
	}
	if !s.validHMAC(req, body) {
		c.Infof("Signature invalid for request %s", reqID)
		http.Error(w, "Signature invalid", http.StatusUnauthorized)
		return
	}
	eventType := req.Header.Get("X-GitHub-Event")
	if eventType != "ping" && eventType != "pull_request" {
		http.Error(w, fmt.Sprintf("Unsupported event type: %s", eventType), http.StatusBadRequest)
		return
	}
	if eventType == "pull_request" {
		var pr pullRequestPost
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&pr); err != nil {
			c.Infof("Failed to parse JSON for request %s: %s", reqID, err)
			http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
			return
		}
		if strings.Contains(pr.Label.Name, s.Label) && pr.PullRequest.State == "open" && pr.Action == "labeled" {
			go s.postSlackMessage(c, pr)
		} else {
			c.Infof("Skipping message Action: %s\tLabel: %s\tState: %s", pr.Action, pr.Label.Name, pr.PullRequest.State)
		}
	}
	c.Infof("Successful handling of update for request %s", reqID)
	w.WriteHeader(http.StatusOK)
}

func (s notifier) postSlackMessage(c appengine.Context, pr pullRequestPost) {
	reqID := appengine.RequestID(c)
	c.Infof("Posting Slack message for request %s", reqID)
	client := urlfetch.Client(c)
	b, err := s.output(pr)
	if err != nil {
		c.Infof("Failed to create message for request %s", reqID)
		return
	}
	r, err := client.Post(s.SlackURL, "application/json; charset=UTF-8", b)
	if err != nil {
		c.Infof("Failed to post Slack message for request %s. Error: %s", reqID, err)
		return
	}
	r.Body.Close()
}

func (s notifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := appengine.NewContext(req)
	c.Infof("Serving request %s", appengine.RequestID(c))
	if strings.HasPrefix(req.URL.Path, "/payload") && req.Method == "POST" {
		s.payload(c, w, req)
		return
	}
	if req.URL.Path == "/" {
		s.status(c, w, req)
		return
	}
	c.Infof("No handler for method: %s\tpath: %s", req.Method, req.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

var statusTemplate = `<!DOCTYPE html>
<html>
	<body>
		<h1>Pull Tabs instance {{ .Instance }}</h1>
		<p>Watching for label: {{ .Label }}</p>
	</body>
</html>
`

func init() {
	tmpl, err := template.New("status").Parse(statusTemplate)
	if err != nil {
		return
	}
	handler := notifier{
		Label:      "awaiting review",
		Message:    "A Pull Request requires review",
		StatusTmpl: tmpl,
	}
	http.Handle("/", handler)
}
