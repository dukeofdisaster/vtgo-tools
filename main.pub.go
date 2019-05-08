package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	st "strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

// we use json.MarshlIndent to print the interface that's returned
func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func handle_it(v ...interface{}) {
	if v != nil {
		panic(v)
	}
}

func makeline() {
	fmt.Println("===============")
}

func main() {
	// We should check for the file flag first
	// we have to use pointers to use these flag values
	filename := flag.String("f", "", "A file of urls/domains to scan")
	flag.Parse()
	//flag.PrintDefaults()
	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// We can instantiate a client & scanner  outside of the rest of the logic,
	//since we'll them one regardless
	client := vt.NewClient("YOUR-API-KEY HERE")
	scanner := client.NewURLScanner()

	if len(os.Args) == 2 {
		_singleArg := os.Args[1]

		// (1) - Validate the URL has a protocol identifier; if not, add it
		if !(st.Contains(_singleArg, "http://") || st.Contains(_singleArg, "https://")) {
			_singleArg = "http://" + _singleArg
			//fmt.Printf("\nNew String: %s", _singleArg)
		}

		// (2) - supplied url will be identified by it's sha256
		// 	   - https://developers.virustotal.com/v3.0/reference#url
		//	   - sha256 id is preferred over base64 for consistent, clean results
		fmt.Println("[+] Analyzing...: " + _singleArg)
		shaobject := sha256.New()
		shaobject.Write([]byte(_singleArg))
		urlID := hex.EncodeToString(shaobject.Sum(nil))
		//fmt.Println(hash)
		//fmt.Println(urlID)

		// (3) - Build a VT URL  out the urlID
		var noscanURL = vt.URL("urls/%s", urlID)

		// build a URL for scans
		//var newscanURL = vt.URL()
		// (?) - with no scan we can use a simple GET
		var urlDoesNotExist = false
		var lastanal = int64(0)
		var thirtydaysago = int64(0)
		var dat map[string]interface{}
		rawresponse, err := client.Get(noscanURL)
		if err != nil {
			log.Println("URL Didn't Exist...")
			urlDoesNotExist = true
			//fmt.Println("FATAL ERROR")
		} else {
			json.Unmarshal(rawresponse.Data, &dat)
			lastanal = int64(dat["attributes"].(map[string]interface{})["last_analysis_date"].(float64))
			thirtydaysago = int64(time.Now().Unix() - 2592000)
		}
		// Dump the json
		//fmt.Printf("%s", rawresponse.Data)

		// this will be type int64, so we'll cast it to float64
		// 30 days in epoch = 2592000
		// 1 day = 86400

		// if the last analysis date < our 30 day window time, we rescan, else, we collect data
		if lastanal <= thirtydaysago || urlDoesNotExist {
			if lastanal != 0 {
				fmt.Printf("\nOld Scan: ")
				fmt.Println(time.Unix(lastanal, 0))
			}

			fmt.Println("Submitting URL for fresh scan...")

			// Scanner has already been instantiated by this point... here we take
			// the URL id and scan it.. this will return  an analysis object...
			// we use the analasysobject ID to get the results of the scan
			analobject, err := scanner.Scan(_singleArg)
			if err != nil {
				log.Fatal(err)
				fmt.Println("Err scanning object... exit 1")
				os.Exit(1)
			}
			var analysisID = analobject.ID
			fmt.Println("Analysis Object ID: " + analysisID)
			fmt.Println("Sleep for scan; max 10 seconds...")

			// time library requires you to pass an increment object * integer amount
			//time.Sleep(1 * time.Second)
			var resultsURL = vt.URL("analyses/%s", analysisID)
			resultsData, err := client.GetObject(resultsURL)
			if err != nil {
				log.Fatal(err)
				fmt.Println("Err in GetObject() on fresh scan")
				os.Exit(1)
			}
			//fmt.Println(resultsData)

			// Below will print as json.Number; havet o convert to Float64 -> Int64 -> Timestamp
			//fmt.Println(resultsData.Attributes["date"])
			newdateFloat, err := resultsData.Attributes["date"].(json.Number).Float64()
			if err != nil {
				log.Fatal(err)
			}

			// convert new date to int64 so it'll print nicely when we pass it to Println
			newdate := int64(newdateFloat)
			fmt.Printf("New Scan Date: ")
			fmt.Println(time.Unix(newdate, 0))
			fmt.Printf("Malicious: %s\n", resultsData.Attributes["stats"].(map[string]interface{})["malicious"])
			fmt.Printf("Harmless: %s\n", resultsData.Attributes["stats"].(map[string]interface{})["harmless"])
			// Note the link Id will always be the id of the url.. since this is a scan ID
			// we have to split it by '-'; the id we want will always be the 2nd item in the split
			strippedID := strings.Split(analysisID, "-")
			var newscanurl = "https://www.virustotal.com/#/url/" + strippedID[1] + "/detection"
			fmt.Println("Link: " + newscanurl)
		} else {
			fmt.Printf("Freshly Scanned: ")
			fmt.Println(time.Unix(lastanal, 0))
			// Pull out the last_analysis_stats object
			var statsobj = dat["attributes"].(map[string]interface{})["last_analysis_stats"]

			// from he last_analysis_stats object, access the value of the "malicious" key..
			// note we assert that it's a float, then cast the float to an in64 to avoid shitty ypriinting
			var maliciouscount = int64(statsobj.(map[string]interface{})["malicious"].(float64))
			var harmlesscount = int64(statsobj.(map[string]interface{})["harmless"].(float64))

			//fmt.Println(statsobj)
			fmt.Printf("Malicious Hits: %d\n", maliciouscount)
			fmt.Printf("Harmless Count: %d\n", harmlesscount)

			// We'll extract the ID too make a plain URL out of since
			// the link returned in the json is only for the api... note this is an outer
			// object of the data so we can access it more easily
			var id = dat["id"].(string)

			// basic url detection syntax is vt.com/#/url/<ID>/detection:
			var detectionurl = "https://www.virustotal.com/#/url/" + id + "/detection"
			fmt.Println("Link: " + detectionurl)
		}

		// Interestingly enough this value will automatically get printed as an actual date
		//fmt.Printf("Object Attributes: %s", rawData.Attributes["last_analysis_date"])
		makeline()
		os.Exit(0)
	}

	// We don't have to validate -f  was given because flag lib does that on its own
	if len(os.Args) == 3 {
		if *filename == "" {
			fmt.Println("No file given")
			os.Exit(3)
		}

		fmt.Printf("Filename: %s", *filename)
		file, err := os.Open(*filename)

		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()

		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		fmt.Println(lines[1])
	}

}
