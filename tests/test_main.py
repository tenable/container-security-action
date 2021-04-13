from  src.main import main
from docker.errors import APIError, TLSParameterError
import pytest, json, mock

def test_get_cve_info_with_empty_findings():
    assert main.get_cve_info([]) == json.dumps({})

def test_get_cve_info_with_findings():
    findings = [{
        "nvdFinding": {
            "cvss_score": "9.1",
            "cve": "test_cve"
        }
    }]
    assert main.get_cve_info(findings) == json.dumps({"test_cve": "9.1"})

def test_get_cve_info_with_findings_with_random():
    findings = [{
        "test": "test"
    }]
    assert main.get_cve_info(findings) == json.dumps({})

@mock.patch("src.main.main.requests")
def test_get_report_with_missing_keys(mock_requests):
    mock_requests.request().text = json.dumps({})
    with pytest.raises(ValueError):
        main.get_report("url", "access", "secret")

@mock.patch("src.main.main.get_response")
def test_get_report(mock_get_response):
    mock_data = {
        "findings": [],
        "malware": [],
        "risk_score": "10"
    }
    mock_get_response.side_effect = [mock_data]
    assert main.get_report("url", "access", "secret") == mock_data

@mock.patch('time.sleep', return_value=None)
@mock.patch("src.main.main.get_response")
def test_get_report_with_retry(mock_get_response, mock_sleep):
    mock_wait = {
        "status": "error",
        "message": "report_not_ready", 
        "reason": "test_wait"
    }
    mock_data = {
        "findings": [],
        "malware": [],
        "risk_score": "10"
    }
    mock_get_response.side_effect = [mock_wait, mock_data]
    assert main.get_report("url", "access", "secret") == mock_data

def test_check_threshold_for_risk():
    
    with pytest.raises(ValueError):
        main.check_threshold(
            9, 
            0, 
            0, 
            5, 
            0, 
            0
        )

def test_check_threshold_for_findings():
    
    with pytest.raises(ValueError):
        main.check_threshold(
            0, 
            10, 
            0, 
            0, 
            6, 
            0
        )

def test_check_threshold_for_malware():
    
    with pytest.raises(ValueError):
        main.check_threshold(
            0, 
            0, 
            3, 
            0, 
            0, 
            1
        )

def test_push_docker_image_with_error():
   
    with pytest.raises(APIError):
        main.push_docker_image("access_key", "secret", "registry", "repo/image", "image", "tag")

@mock.patch("src.main.main.docker")
def test_push_docker_image(mock_docker):
   
    main.push_docker_image("access_key", "secret", "registry", "repo/image", "image", "tag")
    mock_docker.from_env.assert_called()
    