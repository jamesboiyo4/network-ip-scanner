package privateIP

import (
	"encoding/json"
	"fmt"
	"inPacket/logs"
	"io"
	"net/http"
)

type Resp struct {
	//Query       string `json:"query"`
	//Status      string `json:"status"`
	Country string `json:"country"`
	//CountryCode string `json:"countryCode"`
	//Region      string `json:"region"`
	//RegionName  string `json:"regionName"`
	City string `json:"city"`
	//Lat         string `json:"lat"`
	//Lon         string `json:"lon"`
	Isp string `json:"isp"`
	//Org         string `json:"org"`
	//As          string `json:"as"`
}

func (r *Resp) Error() string {
	return fmt.Sprintf("The public ip is located at: %v \t city:%v \t and is serviced by: %v", r.Country, r.City, r.Isp)
}

func throw(country, city, isp string) error {
	return &Resp{country, city, isp}
}

func (pIP *PrivateIP) Location(ip string) {
	defer pIP.wg.Done()
	lg := new(logs.WriteLogs)

	urlAndIP := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, _ := http.Get(urlAndIP)

	respBody, _ := io.ReadAll(resp.Body)

	var respObj Resp
	json.Unmarshal(respBody, &respObj)
	lg.WriteIntoLogFile(throw(respObj.Country, respObj.City, respObj.Isp))
}
