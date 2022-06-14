#!/usr/bin/env python
import os
import json
import time
import re
import sys
import traceback
import docker
import requests
import logging
from docker.errors import APIError, TLSParameterError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
stdoutHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(stdoutHandler)


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
        logger.info(response_dict["reason"])
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
            logger.error(login_response)

        # Gets the image
        client_image = client.images.get(f"{repository}:{tag}")

        # Tags and pushes he image
        tagging_response = client_image.tag(f"registry.cloud.tenable.com/{image}", tag=f"{tag}")
        if not tagging_response:
            logger.error("Tagging failed")
        client.images.push(f"registry.cloud.tenable.com/{image}", tag=f"{tag}")

    except (APIError, TLSParameterError) as e:
        raise e


def scan(repository, tag):
    access_key = str(os.environ["ACCESS_KEY"])
    secret_key = str(os.environ["SECRET_KEY"])
    risk_threshold = int(os.environ["INPUT_RISK_THRESHOLD"])
    findinds_threshold = int(os.environ["INPUT_FINDINGS_THRESHOLD"])
    malware_threshold = int(os.environ["INPUT_MALWARE_THRESHOLD"])
    image = repository.split("/")[1]
    check_thresholds = True if str(os.environ["INPUT_CHECK_THRESHOLDS"]) == "true" else False

    registry = "registry.cloud.tenable.com"
    url = f"https://cloud.tenable.com/container-security/api/v2/reports/library/{image}/{tag}"

    push_docker_image(access_key, secret_key, registry, repository, image, tag)

    response_dict = get_report(url, access_key, secret_key)

    number_of_findings = len(response_dict["findings"])
    risk_score = response_dict["risk_score"]
    number_of_malware_findings = len(response_dict["malware"])
    cve_info = get_cve_info(response_dict["findings"])

    if check_thresholds:
        check_threshold(
            risk_score,
            number_of_findings,
            number_of_malware_findings,
            risk_threshold,
            findinds_threshold,
            malware_threshold
        )

    logger.info(f"::set-output name=risk_score::{risk_score}")
    logger.info(f"::set-output name=number_of_findings::{number_of_findings}")
    logger.info(f"::set-output name=number_of_malware_findings::{number_of_malware_findings}")
    logger.info(f"::set-output name=cve_info::{cve_info}")

    return {
        "risk_score": risk_score,
        "number_of_findings": number_of_findings,
        "number_of_malware_findings": number_of_malware_findings,
        "cve_info": cve_info
    }


if __name__ == "__main__":
    with open('_images.yaml') as f:
        results = {}
        lines = f.readlines()
        for line in lines:
            repo_data = re.search(r"^- (.*): (.*)$", line)
            repo_result = {
                "repo_name": repo_data.group(1),
                "tag_name": repo_data.group(2)
            }

            scan_result = scan(repo_result["repo_name"], repo_result["tag_name"])

            repo_result["scan_result"] = scan_result
            results[repo_result["repo_name"]] = repo_result

        with open('data.json', 'w') as f:
            json.dump(results, f, indent=4)
