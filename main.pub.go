package main

import (
	"flag"
	"fmt"
	"log"
  "encoding/json"
  "encoding/base64"
  "os"
  st "strings"

	vt "github.com/VirusTotal/vt-go"
)

//var fileSHA256 = flag.String("sha256", "", "SHA256 of some file")
//var domain_string = flag.String("domain", "", "Some domain to investigate")

type Stats struct {
	Harmless   int
	Malicious  int
	Suspicious int
	Timeout    int
	Undetected int
}

type Engine struct {
	Category       string
	Engine_Name    string
	Engine_update  string
	Engine_version string
	Method         string
	Result         string
}

type ResponseDict struct {
	Date    int
	Results []Engine
	stats   []Stats
}

// we use json.MarshlIndent to print the interface that's returned
func prettyPrint(i interface{}) string {
  s, _ := json.MarshalIndent(i, "", "\t")
  return string(s)
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
	client := vt.NewClient("xxxYourAPIKeyHerexxxxx")
  scanner := client.NewURLScanner()

  if len(os.Args) == 2 {
    fmt.Println("2 args: program and one other")
    _singleArg := os.Args[1]

    // Validate the URL has a protocol identifier; if not, add it
    if !(st.Contains(_singleArg, "http://") || st.Contains(_singleArg, "https://")) {
      _singleArg = "http://" + _singleArg
      fmt.Printf("\nNew String: %s", _singleArg)
    }
    // we won't need a scan scanner unless the last scan date is too old.
    // encoding the malicious URL as base64 is how we access the URL on vt
    var urlID = base64.RawURLEncoding.EncodeToString([]byte(_singleArg))
    fmt.Println(urlID)
    //os.Exit(1)
    var noscanURL = vt.URL("urls/%s", urlID)

    // with no scan we can use a simple GET
    rawresponse, err := client.Get(noscanURL)
    if err != nil {
      log.Fatal(err)
    }
    fmt.Printf("%s", rawresponse)
    os.Exit(1)
    // After we've validated the URL we can get an analysis object for the url by scanning it
	  analobject, err := scanner.Scan(_singleArg)
    if err != nil {
      log.Fatal(err)
      fmt.Println("Err scanning object... exit 1")
      os.Exit(1)
    }
    // after we've gotten the analysis object it will have an ID; this is used
    // to get the data about the url
    // TODO: Add functionality to rescan if the last scan date is too old
    var id_url = vt.URL("analyses/%s", analobject.ID)
    jdata, err := client.GetObject(id_url)
    if err != nil {
      log.Fatal(err)
    }
    fmt.Printf("\nMalicious: %s", jdata.Attributes["stats"].(map[string]interface{})["malicious"])
    fmt.Printf("Stats %s", jdata.Attributes["stats"])
    os.Exit(0)
  }

  // We don't have to validate -f  was given because flag lib does that on its own
  if len(os.Args) == 3 {
    fmt.Printf("Filename: %s", *filename)
  }
  if *filename == "" {
    fmt.Println("No file given")
  }

  // If we just want to scan one url we don't need a flag for that

  // We should check if there's a protocol identifier; if not add one because we don't want
  // to check domains...
  // TODO: Add functionality for pulling down domain relations with url identification
  //      - NOTE: that should probably only be done when we're given a file to parse
  //fmt.Println(_singleArg)
	//flag.Parse()


	// only for scanning fresh urls; these analysis ID's aren't

	// Scanner returns an analysys object; this will have an ID attributue
	// which we can then use to get the analyses
	//analobject, err := scanner.Scan("www.google.com")
	analobject, err := scanner.Scan("http://www.pepperbagz.com/wp-content/themes/basel/fonts/1c.jpg")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RESULT: %s", analobject.ID)
	var id_url = vt.URL("analyses/%s", analobject.ID)

	// This will return a response object which
	// we can pass directly as a string, or access parts of. the struct is
	// defined as such in vt.go
	/*

		// Response is the top level structure of an API response.
		type Response struct {
		  Data  json.RawMessage        `json:"data"`
		  Meta  map[string]interface{} `json:"meta"`
		  Links Links                  `json:"links"`
		  Error Error                  `json:"error"`
		}

	*/
	// the raw data must still be unmarshalled... for a higiher level
	// functionality ywe must use GetData and send the unmarshalled data to a structure
  // returns vt.Response of type byte[]
/*
	resp2, err := client.Get(id_url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\n\nRAN WITH client.Get() - prints resp2.Data: %s", resp2.Data)
*/
	// Returns an object
	data1, err := client.GetObject(id_url)
	if err != nil {
		log.Fatal(err)
	}

  // since the type of data1.Attributes["stats"] is of type map[string]interface{}
  // to access it we have to acess the value in this way
	fmt.Printf("Ran with client.GetObject(): %s", data1.Attributes["stats"].(map[string]interface{})["malicious"])

  // try to use the value in logic
  // The json object has type json.Number, which must be converted to numeric
  // data type Float64() to be used in arithmetic
  zero, err := data1.Attributes["stats"].(map[string]interface{})["malicious"].(json.Number).Float64()
  if err != nil {
    log.Fatal(err)
  }
  if zero == 0 {
    fmt.Println("True")
  } else {
    fmt.Println("FALSE")
  }
  // here we use a different method by unmarshalling the data without specifying
  // the structure
  // recall that we get errors because we have a type interface{} that doesn't jive
  // with string or int or whatever
  //m := make(map[string]interface{})
  //err := json.Unmarshal(resp2, &m)
  //if err != nil {
  //  log.Fatal(err)
  //}
  //fmt.Println(m["malicious"])
	//var resp3 ResponseDict
/*
	var interf interface{}
	data2, err := client.GetData(id_url, &interf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ran with client.GetData()\n========%s\n========", interf)
	fmt.Printf("data2: %s", data2)
  /**/
	// Now that we've received a response we can parse this with response
}
