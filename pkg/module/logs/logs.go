package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
)

const (
	apiLogsQuery = "v1.0/logs/query"
)

type logRequest struct {
	Limit  int       `json:"limit"`
	Start  int       `json:"start"`
	End    int       `json:"end"`
	Sort   string    `json:"sort"`
	Filter logFilter `json:"filter"`
}

type logFilter struct {
	Op    string           `json:"op"`
	Match []logFilterMatch `json:"match"`
}

type logFilterMatch struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type logResponse struct {
	Count int   `json:"count"`
	Start int   `json:"start"`
	End   int   `json:"end"`
	Logs  []log `json:"logs"`
}

type log struct {
	Timestamp  int               `json:"timestamp"`
	TraceID    string            `json:"traceID"`
	SpanID     string            `json:"spanID"`
	Message    string            `json:"message"`
	Severity   string            `json:"severity"`
	Attributes map[string]string `json:"attributes"`
}

type LogParameters struct {
	TraceID  string
	SpanID   string
	Severity string
	Filter   string
	Follow   bool
}

type LogsClient struct {
	client xhttp.Clientx
}

func NewLogsClient() *LogsClient {
	return &LogsClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *LogsClient) PrintLogs(ctx context.Context, auth *config.AuthConfig, writer io.Writer, params *LogParameters) error {
	vc := config.GetVerifyContext(ctx)

	currTime := time.Now()
	endTime := currTime.UnixMilli()
	startTime := currTime.Add(-time.Minute * 30).UnixMilli()

	if params == nil {
		params = &LogParameters{}
	}

	lfilter, err := c.getFilter(params.TraceID, params.SpanID, params.Severity, params.Filter)
	if err != nil {
		return err
	}

	logRequest := &logRequest{
		Limit:  500,
		Start:  int(startTime),
		End:    int(endTime),
		Sort:   "asc",
		Filter: *lfilter,
	}

	w := tabwriter.NewWriter(os.Stdout, 10, 1, 2, ' ', tabwriter.Debug)

	isFirstLog := true
	for isFirstLog || params.Follow {
		logs, err := c.getLogs(ctx, auth, logRequest)
		if err != nil {
			vc.Logger.Warnf("unable to get logs; err=%v", err)
			continue
		}

		if len(logs) > 0 {
			c.printLogs(ctx, w, logs, isFirstLog)
			isFirstLog = false
			// new start time will be the timestamp of the last log
			logRequest.Start = logs[len(logs)-1].Timestamp + 1
		}

		time.Sleep(10 * time.Second)
		logRequest.End = int(time.Now().UnixMilli())
	}

	return nil
}

func (c *LogsClient) printLogs(_ context.Context, w *tabwriter.Writer, logs []log, isFirstLog bool) {
	if isFirstLog {
		fmt.Fprintln(w, "Timestamp\tTrace ID\tSpan ID\tMessage\tSeverity")
	}

	for _, v := range logs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strconv.Itoa(v.Timestamp), v.TraceID, v.SpanID, v.Message, v.Severity)
	}

	w.Flush()
}

func (c *LogsClient) getLogs(ctx context.Context, auth *config.AuthConfig, logReq *logRequest) ([]log, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiLogsQuery))

	body, err := json.Marshal(logReq)
	if err != nil {
		return nil, err
	}

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Post(ctx, u, headers, body)
	if err != nil {
		vc.Logger.Errorf("unable to get the logs; err=%s", err.Error())
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsOld(ctx, response, "unable to get logs"); err != nil {
			vc.Logger.Errorf("unable to get the logs; err=%s", err.Error())
			return nil, err
		}

		return nil, fmt.Errorf("unable to get the logs")
	}

	logResp := &logResponse{}
	if err = json.Unmarshal(response.Body, logResp); err != nil {
		return nil, fmt.Errorf("unable to get the logs")
	}

	return logResp.Logs, nil
}

func (c *LogsClient) getFilter(traceID, spanID, severity, filterStr string) (*logFilter, error) {

	var matches []logFilterMatch

	if traceID != "" {
		m := logFilterMatch{"traceID", "eq", traceID}
		matches = append(matches, m)
	}

	if spanID != "" {
		m := logFilterMatch{"spanID", "eq", spanID}
		matches = append(matches, m)
	}

	if severity != "" {
		m := logFilterMatch{"severity", "eq", severity}
		matches = append(matches, m)
	}

	if filterStr != "" {

		filters := strings.Split(filterStr, "&")

		if len(filters) > 0 {

			for _, f := range filters {

				kv := strings.Split(f, "=")

				if len(kv) != 2 {
					return nil, errors.New(i18n.Translate("custom filter string is invalid."))
				}

				m := logFilterMatch{kv[0], "eq", kv[1]}
				matches = append(matches, m)

			}
		}
	}

	return &logFilter{Op: "AND", Match: matches}, nil
}
