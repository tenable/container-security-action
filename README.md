# container-security-action
Tenable's Container security action

This action can be used to trigger a container security scan for your build images. The user must have a Tenable.io account and also a license for container security. The action will upload the image to the tenable registry which kicks of the scan. This detailed results for each scan can be found within the container security dashboard on Tenable.io. The results can also be 
Specifying the given thresholds, SLAs can be enforced before deployments. 

## Usage

Describe how to use your action here.

### Example workflow

```yaml
name: Test Container security workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Set up QEMU
        uses: docker/setup-qemu-action@v1
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v1
      - name: Build
        uses: docker/build-push-action@v2
        with:
            context: .
            push: false
            tags: user/app:latest
            load: true
      - name: Runs the container security scan
        uses: tenable/container-security-action@v0
        id: consec
        with:
          repo_name: user/app
          tag_name: latest
        env:
          ACCESS_KEY: ${{ secrets.ACCESS_KEY }}
          SECRET_KEY: ${{ secrets.SECRET_KEY }}
```

### Inputs

| Input                                             | Description                                        |
|------------------------------------------------------|-----------------------------------------------|
| `repo_name`  | Repository name for image built, e.g user/app   |
| `tag_name`   | Tag name associated to the image   |
| `check_thresholds` _(optional)_  | If the action should check results against the set thresholds  |
| `risk_threshold` _(optional)_  | Risk threshold to be checked based on the risk score of the image  |
| `findings_threshold` _(optional)_  | Findings threshold to be checked based on the number of vulnerabilities found in the image |
| `malware_threshold` _(optional)_  | Malware threshold to be checked based on the number of malware findings in the image |

### Outputs

| Output                                             | Description                                        |
|------------------------------------------------------|-----------------------------------------------|
| `risk_score`  | Risk score given to the image after the scan |
| `number_of_findings`  | Number of vulnerabilites found in the image |
| `number_of_malware_findings`  | Number of malware findings in the image |
| `cve_info`  | CVE info where you have all the cves found along with the risk |


### Providing secrets
The Tenable.io access key and secret key need to be set in your repository secrets and provided the following way to the action
```yaml
    env:
        ACCESS_KEY: ${{ secrets.ACCESS_KEY }}
        SECRET_KEY: ${{ secrets.SECRET_KEY }}
```
The action uses these secrets to push the image to the tenable registry and to get the scan results.

### Using outputs

The outputs can be accessed using the following way

```yaml
    - name: Gets the risk score
        run: echo "The risk score ${{ steps.consec.outputs.risk_score }}"
    - name: Gets the risk scores for cves
        run: echo "The cve information is ${{ steps.consec.outputs.cve_info }}"
```

### Lincese
The project is licensed under the MIT license.
