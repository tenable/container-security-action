#!/usr/bin/env python
import os, json, time
import sys, traceback
import docker
import requests
from docker.errors import APIError, TLSParameterError


def get_cve_info(findings):
    """
    Returns a json string cve info and associated risk
    """
    cve_info = {}
    for finding in findings:
        if "nvdFinding" in finding:
            if "cve" in finding["nvdFinding"] and "cvss_score" in finding["nvdFinding"]:
                cve_info[finding["nvdFinding"]["cve"]] = finding["nvdFinding"]["cvss_score"]
    
    return json.dumps(cve_info)
    

def get_response(url, headers):
    """
    Gets the report response from the API
    """
    response = requests.request("GET", url, headers=headers)
    response_dict = json.loads(response.text)
    return response_dict

def get_report(url, access_key, secret_key):
    """
    Gets the container scan report
    """
    headers = {"Accept": "application/json", "x-apikeys": f"accessKey={access_key};secretKey={secret_key}"}
    response_dict = get_response(url, headers)

    while "status" in response_dict and response_dict["status"] == "error" and response_dict["message"] == "report_not_ready":
        print(response_dict["reason"])
        time.sleep(30)
        response_dict = get_response(url, headers)
    
    if "findings" not in response_dict or "risk_score" not in response_dict or "malware" not in response_dict:
        raise ValueError("Finding, risk score or malware not returned")

    return response_dict

def check_threshold(risk_score, number_of_findings, number_of_malware_findings, risk_threshold, findinds_threshold, malware_threshold):
    risk_score = float(risk_score)       
    if risk_score > risk_threshold:
        raise ValueError("Risk score has exceeded threshold")

    if number_of_findings > findinds_threshold:
        raise ValueError("Number of findings has exceeded threshold")

    if number_of_malware_findings > findinds_threshold:
        raise ValueError("Malware found has exceeded threshold")

def push_docker_image(access_key, secret_key, registry, repository, image, tag):
    """
    Pushes the docker image to the tenable registry
    """
    try:
        client = docker.from_env()
        login_response = client.login(username=access_key, password=secret_key, registry=registry)
        if login_response["Status"] != "Login Succeeded":
            print(login_response)
        
        # Gets the image
        client_image = client.images.get(f"{repository}:{tag}")
        
        # Tags and pushes he image
        tagging_response = client_image.tag(f"registry.cloud.tenable.com/{image}", tag=f"{tag}")
        if not tagging_response:
            print("Tagging failed")
        client.images.push(f"registry.cloud.tenable.com/{image}", tag=f"{tag}")

    except (APIError,TLSParameterError) as e:
        raise e 

def main():

    access_key = str(os.environ["ACCESS_KEY"])
    secret_key = str(os.environ["SECRET_KEY"])
    risk_threshold = int(os.environ["INPUT_RISK_THRESHOLD"])
    findinds_threshold = int(os.environ["INPUT_FINDINGS_THRESHOLD"])
    malware_threshold = int(os.environ["INPUT_MALWARE_THRESHOLD"])
    block_builds = str(os.environ["INPUT_BLOCK_BUILDS"])
    repository = str(os.environ["INPUT_REPO_NAME"])
    image = repository.split("/")[1]
    tag = str(os.environ["INPUT_TAG_NAME"])

    registry = "registry.cloud.tenable.com"
    url = f"https://cloud.tenable.com/container-security/api/v2/reports/library/{image}/{tag}"   

    push_docker_image(access_key, secret_key, registry, repository, image, tag)
    response_dict = get_report(url, access_key, secret_key)

    number_of_findings = len(response_dict["findings"])
    risk_score =  response_dict["risk_score"]
    number_of_malware_findings = len(response_dict["malware"])
    cve_info = get_cve_info(response_dict["findings"])

    # if block_builds is "true":
    #     # return as we don't need to check anything
    #     check_threshold(risk_score, number_of_findings, number_of_malware_findings, risk_threshold, findinds_threshold, malware_threshold)

    print(f"::set-output name=risk_score::{risk_score}")
    print(f"::set-output name=number_of_findings::{number_of_findings}")
    print(f"::set-output name=number_of_malware_findings::{number_of_malware_findings}")
    print(f"::set-output name=cve_info::{cve_info}")

if __name__ == "__main__":
    main()
