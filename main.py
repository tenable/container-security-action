#!/usr/bin/env python
import os, json
import sys, traceback
import docker
# from docker.errors import APIError, TLSParameterError

import requests


def main():

    access_key = int(os.environ["ACCESS_KEY"])
    secret_key = int(os.environ["SECRET_KEY"])
    # risk_threshold = int(os.environ["RISK_THRESHOLD"])
    # findinds_threshold = int(os.environ["FINDINGS_THRESHOLD"])
    # malware_threshold = int(os.environ["MALWARE_THRESHOLD"])
    image = int(os.environ["IMAGE_NAME"])
    tag = int(os.environ["TAG_NAME"])

    # try:
        # client = docker.from_env()
        # login_response = client.login(username=access_key, password=secret_key, registry="registry.cloud.tenable.com")
        # if login_response["Status"] is not "Login Succeeded":
        #     raise "Login Failed"
        
        # Gets the image
        # image = client.images.get(f"{image}:{tag}")
        
        # Tags and pushes he image
        # tagging_response = image.tag(f"registry.cloud.tenable.com/{image}", tag=f"{tag}")
        # if not tagging_response:
        #     print("Tagging failed")
        # print(client.images.push(f"registry.cloud.tenable.com/{image}", tag=f"{tag}"))
    
    # except Exception as e:
    #     raise e

    url = "https://cloud.tenable.com/container-security/api/v2/reports/library/cvetest/v1"


    headers = {"Accept": "application/json", "x-apikeys": f"accessKey={access_key};secretKey={secret_key}"}

    response = requests.request("GET", url, headers=headers)

    # response = requests.request("GET", url, headers=headers, params=querystring)

    response_dict = json.loads(response.text)
    number_of_findings = response_dict["findings"]
    risk_score =  response_dict["risk_score"]
    number_of_malware_findings = response_dict["malware"]

    print(f"::set-output name=risk_score::{risk_score}")


if __name__ == "__main__":
    main()
