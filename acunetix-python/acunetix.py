import requests
import json
import time
import urllib3
from datetime import datetime

ACUNETIX_API_KEY = ""
ACUNETIX_API_HOST = ""

HEADERS = { 
        'Content-Type': 'application/json',
        'X-Auth': ACUNETIX_API_KEY  
}

def first_post_acunetix_request(target):
    """
    function to post target and return the `target id`
    """
    targets_url = f"{ACUNETIX_API_HOST}/api/v1/targets"
    targets_payload = json.dumps({
        "address": target
    })
    targets_response = requests.request(
        "POST", targets_url, headers=HEADERS, data=targets_payload, verify=False)
    target_id = targets_response.json()
    print("The target_id = " + target_id["target_id"])
    return target_id["target_id"]

def acunetix_scan(target):
    urllib3.disable_warnings()
    #Get target id from first post request to acunetix
    target_id = first_post_acunetix_request(target)
    # use the target_id to schedule the scan & get the scan_location
    scans_url = f"{ACUNETIX_API_HOST}/api/v1/scans"
    scans_payload = json.dumps({
        "profile_id": "11111111-1111-1111-1111-111111111111",
        "incremental": False,
        "schedule": {
            "disable": False,
            "start_date": None,
            "time_sensitive": False
        },
        "user_authorized_to_scan": "yes",
        "target_id": target_id
    })
    scans_response = requests.request(
        "POST", scans_url, headers=HEADERS, data=scans_payload, verify=False)
    scan_location = scans_response.headers["Location"]
    print("The scan location is = " + scan_location)
    # use the scan_location in a while loop to end it if the scan is completed
    LoopCondition = True
    while LoopCondition:
        # Get status of the scan
        status_n_results_url = f"{ACUNETIX_API_HOST}{scan_location}"
        status_n_results_response = requests.request(
            "GET", status_n_results_url, headers=HEADERS, data={}, verify=False)
        status_n_results = status_n_results_response.json()
        status = status_n_results["current_session"]["status"]
        print("The scan status is : " + status + " " + str(datetime.now()))
        # Get result_id to get the vulnerabilities list
        scan_results_url = f"{ACUNETIX_API_HOST}{scan_location}/results"
        scan_results_response = requests.request(
            "GET", scan_results_url, headers=HEADERS, data={}, verify=False)
        scan_results = scan_results_response.json()
        result_id = scan_results["results"][0]["result_id"]
        if status != "completed":
            vulnerabilities_list_url = f"{ACUNETIX_API_HOST}{scan_location}/results/{result_id}/vulnerabilities"
            vulnerabilities_list_response = requests.request(
                "GET", vulnerabilities_list_url, headers=HEADERS, data={}, verify=False)
            vulnerabilities_list = vulnerabilities_list_response.json()
            print(vulnerabilities_list)
            vulnerabilities = vulnerabilities_list["vulnerabilities"]
            for vulnerability in vulnerabilities:
                #print the vulnerability single block 
                print(vulnerability)
            time.sleep(1)
        else:
            LoopCondition = False
            break
