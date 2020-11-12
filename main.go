package main

import (
	"bufio"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-scan"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	endpoint = "https://api.imgur.com/3/image"
)

// oauth configuration
var config = &oauth2.Config{
	ClientID:     "16958ad0bd36ae8",
	ClientSecret: "40f37038e13285da76657c73a22d9840b9dae393",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://api.imgur.com/oauth2/authorize",
		TokenURL: "https://api.imgur.com/oauth2/token",
	},
}

func osUserCacheDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	return filepath.Join(home, ".cache")
}

func tokenCacheFile(config *oauth2.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientID))
	hash.Write([]byte(config.ClientSecret))
	if len(config.Scopes) > 0 {
		hash.Write([]byte(config.Scopes[0]))
	}
	fn := fmt.Sprintf("imgur-api-tok%v", hash.Sum32())
	return filepath.Join(osUserCacheDir(), url.QueryEscape(fn))
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := new(oauth2.Token)
	err = gob.NewDecoder(f).Decode(t)
	return t, err
}

func saveToken(file string, token *oauth2.Token) error {
	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("Warning: failed to cache oauth2 token: %v", err)
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(token)
}

func getOAuthClient(config *oauth2.Config) (*http.Client, error) {
	cacheFile := tokenCacheFile(config)
	token, err := tokenFromFile(cacheFile)
	if err != nil {
		if token, err = tokenFromWeb(config); err != nil {
			return nil, err
		}
		if err = saveToken(cacheFile, token); err != nil {
			return nil, err
		}
	}

	return config.Client(context.Background(), token), nil
}

func tokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	config.RedirectURL = ""
	authUrl := config.AuthCodeURL("")
	u2, err := url.Parse(authUrl)
	if err != nil {
		return nil, fmt.Errorf("Parse error: %v", err)
	}
	v := u2.Query()
	v.Set("response_type", "pin")
	u2.RawQuery = v.Encode()
	authUrl = u2.String()

	go openUrl(authUrl)

	fmt.Print("PIN: ")
	b, _, err := bufio.NewReader(os.Stdin).ReadLine()
	if err != nil {
		return nil, fmt.Errorf("Canceled")
	}

	v = url.Values{
		"grant_type":    {"pin"},
		"pin":           {strings.TrimSpace(string(b))},
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
	}
	res, err := http.DefaultClient.Post(
		config.Endpoint.TokenURL,
		"application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("Token exchange error: %v", err)
	}
	defer res.Body.Close()

	var result struct {
		Access    string        `json:"access_token"`
		Refresh   string        `json:"refresh_token"`
		ExpiresIn time.Duration `json:"expires_in"`
		Id        string        `json:"id_token"`
	}
	if err = json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("Token exchange error: %v", err)
	}

	return &oauth2.Token{
		AccessToken:  result.Access,
		RefreshToken: result.Refresh,
		Expiry:       time.Now().Add(result.ExpiresIn),
	}, nil
}

func openUrl(u string) error {
	cmd := "xdg-open"
	args := []string{cmd, u}
	if runtime.GOOS == "windows" {
		cmd = "rundll32.exe"
		args = []string{cmd, "url.dll,FileProtocolHandler", u}
	} else if runtime.GOOS == "darwin" {
		cmd = "open"
		args = []string{cmd, u}
	}
	cmd, err := exec.LookPath(cmd)
	if err != nil {
		return err
	}
	p, err := os.StartProcess(cmd, args, &os.ProcAttr{Dir: "", Files: []*os.File{nil, nil, os.Stderr}})
	if err != nil {
		return err
	}
	defer p.Release()
	return nil
}

var anonymous = flag.Bool("a", false, "Post as anonymous")

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage of imgur [-a] [file]`)
		flag.PrintDefaults()
	}
	flag.Parse()

	var b []byte
	var err error

	if flag.NArg() == 0 {
		b, err = ioutil.ReadAll(os.Stdin)
	} else {
		b, err = ioutil.ReadFile(flag.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err.Error())
		os.Exit(1)
	}

	params := url.Values{"image": {base64.StdEncoding.EncodeToString(b)}}

	var res *http.Response

	if *anonymous {
		req, err := http.NewRequest("POST", endpoint, strings.NewReader(params.Encode()))
		if err != nil {
			fmt.Fprintln(os.Stderr, "post:", err.Error())
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Client-ID "+config.ClientID)

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "post:", err.Error())
			os.Exit(1)
		}
	} else {
		client, err := getOAuthClient(config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "auth:", err.Error())
			os.Exit(1)
		}

		res, err = client.PostForm(endpoint, params)
		if err != nil {
			fmt.Fprintln(os.Stderr, "post:", err.Error())
			os.Exit(1)
		}
	}
	if res.StatusCode != 200 {
		var message string
		err = scan.ScanJSON(res.Body, "data/error", &message)
		if err != nil {
			message = res.Status
		}
		fmt.Fprintln(os.Stderr, "post:", message)
		os.Exit(1)
	}
	defer res.Body.Close()

	var link string
	err = scan.ScanJSON(res.Body, "data/link", &link)
	if err != nil {
		fmt.Fprintln(os.Stderr, "post:", err.Error())
		os.Exit(1)
	}
	fmt.Println(link)
}
