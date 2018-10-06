__author__ = 'ashishkushwaha'
import requests, json, pprint
from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)
pagesize = '1000'

api_url_base = "https://10.120.15.187:8446/sepm/api/v1/"
authentication_url = "https://10.120.15.187:8446/sepm/api/v1/identity/authenticate"
# if output is required in JSON format
json_format = True

payload = {"username" : "admin", "password" : "Symantec123","domain" : ""}
headers = {"Content-Type":"application/json"}

#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL' # necessary
#r = requests.Session()      # Start session in order to store the SessionID Cookie
r = requests.post(authentication_url, verify=False, headers=headers, data=json.dumps(payload))
api_token = (r.json()["token"])

headers = {'pageSize':pagesize,'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

# REST API URL to fetch information
groups_url = '{0}groups'.format(api_url_base)
fingerprint_url = '{0}policy-objects/fingerprints'.format(api_url_base)
computers_url = '{0}computers'.format(api_url_base)
onlinestatus_url = '{0}api/v1/stats/client/onlinestatus'.format(api_url_base)
client_version = '{0}api/v1/stats/client/version'.format(api_url_base)
client_content = '{0}api/v1/stats/client/content'.format(api_url_base)
gup_status = '{0}api/v1/gup/status'.format(api_url_base)
license_url='{0}api/v1/licenses/summary'.format(api_url_base)
criticalevent_url = '{0}api/v1/events/critical'.format(api_url_base)
contentsource_url = '{0}api/v1/stats/client/content/sources'.format(api_url_base)
infection_url ='{0}api/v1/client/infection/Week/'.format(api_url_base)
threat_url ='{0}api/v1/stats/threat'.format(api_url_base)
policies_summary = '{0}api/v1/policies/summary'.format(api_url_base)


def aggregate(return_info,numberOfElements):
    itr =0
    while itr <= (numberOfElements-1):
        #pprint.pprint(endpoints_info['content'][itr]['ipAddresses'][0])
        groupID=return_info['content'][itr]['id']
        groupFullPath=return_info['content'][itr]['fullPathName']
        groupName=return_info['content'][itr]['name']
        groupPolicySerialNumber=return_info['content'][itr]['policySerialNumber']
        groupNumberOfPhysicalComputers = return_info['content'][itr]['numberOfPhysicalComputers']

        itr = itr + 1

#Function to fetch information based on URL passed and response
def get_info(url,params):
    api_url = url
    params = params
    response = requests.get(api_url, headers=headers,verify=False, params=params)
    if response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        return response.status_code

@app.route("/")
def home():
    # REST API URL to fetch information
    #groups_url = '{0}groups'.format(api_url_base)
    query = request.args.get("hostname")
    print(query)
    if query == '':
        query = request.args.get("LP000007019202")


    url = '{0}computers?'.format(api_url_base)
    params = {'computerName':'{0}'.format(query)}
    return_info = get_info(url,params)
    if return_info is not 200:
        if return_info['numberOfElements'] != 0:
            clientInfo = return_info['content']
        else:
            clientInfo = {

            }
    else:
        print('[!] Request Failed', 'Error Code : {0}'.format(return_info))

    return render_template("index.html",clientInfo=clientInfo)

@app.route(("/gupServerStatus"))
def gupServerStatus():
    gup_status_url = '{0}api/v1/gup/status'.format(api_url_base)
    params={}
    response_info = get_info(gup_status_url,params)
    if response_info is not 200:
        pprint.pprint(response_info)
        gupServerStatus=response_info
        #print('Total Endpoints:',response_info['totalElements'])
        #print(response_info["totalElements"])
    else:
        print('[!] Request Failed, {0}')


    return render_template("gupServerStatus.html",gupServerStatus=gupServerStatus)

@app.route("/clientVersions")
def clientVersion():
    client_version_url = '{0}api/v1/stats/client/version'.format(api_url_base)
    params={}
    response_info = get_info(client_version_url,params)
    if response_info is not 200:
        pprint.pprint(response_info)
        data=response_info
        #print('Total Endpoints:',response_info['totalElements'])
        #print(response_info["totalElements"])
    else:
        print('[!] Request Failed, {0}')

    return render_template("clientVersions.html",clientVersions=data)

@app.route("/clientDefStatus")
def clientDefStatus():
    client_content_url = '{0}api/v1/stats/client/content'.format(api_url_base)
    params={}
    response_info = get_info(client_content_url,params)
    if response_info is not 200:
        pprint.pprint(response_info)
        data=response_info
        #print('Total Endpoints:',response_info['totalElements'])
        #print(response_info["totalElements"])
    else:
        print('[!] Request Failed, {0}')
    return render_template("clientDefStatus.html",clientDefStatus=data)


@app.route("/admins")
@app.route("/updateContent")
@app.route("/avdefLatest")
@app.route("/replicationStatus")
@app.route("/licenses")
@app.route("/clientContent")



@app.route('/')
def root():
    # return app.send_static_file('index.html')
    return render_template('index.html')



if __name__ =='__main__':
    app.run(port=5002)
