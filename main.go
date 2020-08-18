/*
mabe by pikpikcu
happy hunting :)
*/

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var version = " v0.1[Beta]"
var creator = "pikpikcu"
var domains string
var payloads string
var output string

//var userAgent string
var timeout int
var threads int
var delay int
var verbose bool

func Banner() {
	color.HiCyan(`

                                    ████     ██████   ███ 
		                   ▒▒███    ███▒▒███ ▒▒▒  	
		  ██████  ████████  ▒███   ▒███ ▒▒▒  ████ 
		 ███▒▒███▒▒███▒▒███ ▒███  ███████   ▒▒███ 
		▒███ ▒▒▒  ▒███ ▒▒▒  ▒███ ▒▒▒███▒     ▒███ 
		▒███  ███ ▒███      ▒███   ▒███      ▒███ 
		▒▒██████  █████     █████  █████     █████
		 ▒▒▒▒▒▒  ▒▒▒▒▒     ▒▒▒▒▒  ▒▒▒▒▒     ▒▒▒▒▒  ` + version)

	color.HiYellow("\n\t--+=[crlfi:- Check Vulnerabilty crlf injection]")
	color.HiGreen("\t--+=[Codename: " + creator + "]")
	color.HiRed("\t--+=[https://github.com/pikpikcu]")
	color.HiRed("\n")

}
func VarFunction(cmd *cobra.Command, args []string) {
	var wg sync.WaitGroup
	if threads <= 0 {
		//fmt.Println("Threads must be larger than 0")
		os.Exit(1)
	}
	payloadread := fileReader(payloads)
	domainsURL := fileReader(domains)
	prosesrun := pb.New(len(domainsURL) * len(payloadread))

	for _, domain := range domainsURL {
		for _, payload := range payloadread {

			fuzzedURL := fuzzURL(domain, payload)

			for ithreads := 0; ithreads < threads; ithreads++ {
				for _, requestURI := range *fuzzedURL {
					if verbose == false {
						prosesrun.Start()
					}
					wg.Add(1)
					prosesrun.Increment()
					go makeRequest(requestURI, timeout, &wg)
					if delay > 0 {
						time.Sleep(time.Duration(delay) * time.Millisecond)
					}
					wg.Wait()
				}
			}
			wg.Wait()
		}
	}
	prosesrun.Finish()
}

func fuzzURL(domain string, payload string) *[]string {
	var fuzzedURL []string
	var fuzzedParams []string

	// Make sure parameter are present
	if strings.Contains(domain, "?") {
		paramStr := strings.Split(domain, "?")[1]
		params := strings.Split(paramStr, "&")
		domainPrefix := strings.Split(domain, "?")[0]
		URL := domainPrefix + "?"

		paramFuzzCount := 0
		// Rebuild parameters so we can work with each parameter individually (I may be doing this wrong)
		// Clear list before concatentation again
		fuzzedParams = nil
		for _, param := range params {
			fuzzedParams = append(fuzzedParams, param)

			if paramFuzzCount != (len(params) - 1) {
				fuzzedParams = append(fuzzedParams, "&")
			}
			paramFuzzCount += 1
		}

		// Inject payload into each parameter consecutively.  We don't want to
		// have server errors for actions that could require specific strings
		for paramPayloadCount := 0; paramPayloadCount < len(fuzzedParams); paramPayloadCount++ {
			finalFuzzedParams := make([]string, len(fuzzedParams))
			copy(finalFuzzedParams, fuzzedParams)
			finalFuzzedParams[paramPayloadCount] = fuzzedParams[paramPayloadCount] + payload

			flattenedURL := URL + strings.Join(finalFuzzedParams[:], "")
			fuzzedURL = append(fuzzedURL, flattenedURL)
		}
	}

	//Fuzz endpoints.  Keeping this seperated from parameters.  Maybe add flags for types of fuzzing later?
	u, err := url.Parse(domain)
	if err != nil {
		panic(err)
	}

	endpoint := u.Path
	scheme := u.Scheme
	host := u.Host

	for endpointPayloadCount := 0; endpointPayloadCount < strings.Count(endpoint, "/"); endpointPayloadCount++ {
		finalEndpoint := replaceNth(endpoint, "/", "/"+payload, endpointPayloadCount+1)
		finalEndpointUrl := []string{scheme, "://", host, finalEndpoint}
		flattenedURL := strings.Join(finalEndpointUrl, "")
		fuzzedURL = append(fuzzedURL, flattenedURL)
	}

	return &fuzzedURL
}

// Thanks stackoverflow
func replaceNth(s, old, new string, n int) string {
	i := 0
	for m := 1; m <= n; m++ {
		x := strings.Index(s[i:], old)
		if x < 0 {
			break
		}
		i += x
		if m == n {
			return s[:i] + new + s[i+len(old):]
		}
		i += len(old)
	}
	return s
}

func fileReader(ulist string) []string {
	var buffer []string
	file, err := os.Open(ulist)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		list := scanner.Text()
		buffer = append(buffer, list)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return buffer

}

func makeRequest(uri string, timeoutFlag int, wg *sync.WaitGroup) {
	defer wg.Done()

	URL := uri

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(timeoutFlag) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}

	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		if verbose == true {
			fmt.Println(err)
		}
		return
	}
	//req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	if err != nil {
		if verbose == true {
			fmt.Println(err)
		}
		return
	}

	if verbose == true {
		fmt.Printf("%s (Status : %d)\n", URL, resp.StatusCode)
	}

	for key := range resp.Header {
		if key == "Injected-Header" {
			if output != "" {
				f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					if verbose == true {
						fmt.Println(err)
					}
				}
				f.WriteString(URL + "\n")
			}
			fmt.Println("[+] is Vulnerable" + URL)
		}
	}
}

func init() {
	rootCmd.AddCommand(crlfi())
}

var mainContext context.Context

var rootCmd = &cobra.Command{
	Use:          "crlfi",
	SilenceUsage: true,
}

func Execute() {
	var cancel context.CancelFunc
	mainContext, cancel = context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case <-signalChan:
			// caught CTRL+C
			fmt.Println("\n[!] Keyboard interrupt detected, terminating.")
			cancel()
			os.Exit(1)
		case <-mainContext.Done():
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
func main() {
	Execute()
}
func crlfi() *cobra.Command {
	Banner()
	crlfi := &cobra.Command{
		Use: "url",
		//Short: "Scanner for all your CRLF Vulnerabilty",
		Short: "",
		Run:   VarFunction,
	}

	crlfi.Flags().StringVarP(&domains, "file", "f", "", "Location file domains")
	crlfi.Flags().StringVarP(&payloads, "payloads", "p", "payloads.txt", "Location of payloads to generate on requests")
	crlfi.Flags().StringVarP(&output, "output", "o", "", "Location to save results")
	//crlfi.Flags().StringVarP(&userAgent, "user-agent", "u", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36", "User agent for requests")
	crlfi.Flags().IntVarP(&timeout, "timeout", "", 10, "The amount of time needed to close a connection ")
	crlfi.Flags().IntVarP(&delay, "delay", "d", 0, "The time each threads waits between requests in milliseconds")
	crlfi.Flags().IntVarP(&threads, "threads", "t", 1, "Number of threads to run crlfi on")
	crlfi.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	crlfi.MarkFlagRequired("domains")

	return crlfi
}
func init() {
	fmt.Printf("")
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}
