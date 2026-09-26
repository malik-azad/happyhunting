# Cloud and Containers

Where the boundary between a network and an API disappears. Most cloud findings
come from one of three places: an over-permissive identity, an exposed
management interface, or a credential that leaked into somewhere it should not
have.

## Contents

- [How cloud differs](#how-cloud-differs)
- [Cloud metadata](#cloud-metadata)
- [AWS](#aws)
- [Azure](#azure)
- [GCP](#gcp)
- [Containers](#containers)
- [Kubernetes](#kubernetes)
- [Cloud-specific bug classes](#cloud-specific-bug-classes)
- [Reporting](#reporting)

---

## How cloud differs

Four things change the way you work, and it is worth being explicit about them
because the old habits actively mislead you.

**There is no perimeter.** "Internal" traffic is frequently unauthenticated,
because a VPC is treated as a security boundary and it is not one. A service on
a private subnet with no authentication is a common and entirely realistic
finding.

**The API is the product.** There is usually no web interface to click, so
recon becomes reading IAM policies and enumerating API versions.

**Credentials outlive the person.** Access keys, service account tokens, and
managed identities persist after staff leave. Finding one in an old repository
or a build log is the single most common cloud compromise.

**Everything is logged.** CloudTrail, Azure Monitor, and GCP Audit Logs are on
by default and are read by somebody. The old advice about being quiet applies
with much less slack than it did on a corporate LAN.

---

## Cloud metadata

The single highest-value target in any cloud engagement, because the metadata
service hands out credentials to anything running inside the instance, without
needing authentication.

```bash
# AWS, IMDSv1. No header required, which is the vulnerability.
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# The role name comes from the previous call. The response is a JSON blob
# containing AccessKeyId, SecretAccessKey, and Token.
```

```bash
# AWS, IMDSv2, which requires a token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**IMDSv2 is the fix and it is worth reporting either way.** A target running
IMDSv1 only is a real finding. A target running IMDSv2, where the token flow
fails, is configured correctly, and reporting that is the difference between a
useful assessment and noise.

```bash
# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# This is the important one. It is a flat file of every identity on the instance.
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# The response is a bearer token. Use it against the management API.
```

```bash
# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Or, in GCP-native tooling
gcloud auth application-default print-access-token
```

```bash
# Make the metadata service reachable before you conclude it is not
# This is the SSRF-to-cloud-credentials chain, and it is very common.
# You need an SSRF, then a redirector, because metadata services block
# redirects to themselves.
# Use a controlled redirect service, and only where the RoE permits it.
```

**Prove the SSRF, then stop.** Demonstrating that the metadata service is
reachable from your serverless function is a complete finding. Retrieving the
credentials turns it into an incident, and the client can test that themselves
on a schedule. Say so in the report and let them decide.

```bash
# If you are asked to demonstrate, do it against your own testing account
curl -s http://127.0.0.1/latest/meta-data/iam/security-credentials/ | head -20
# and rotate anything you touched immediately afterwards
```

---

## AWS

```bash
# Credentials in the environment, which is where they always are
env | grep -i aws
cat ~/.aws/credentials
cat ~/.aws/config
# And on a target
env | grep -i "aws\|secret\|token\|key"
find / -name "*.pem" 2>/dev/null
cat /proc/self/environ | tr '\0' '\n' | grep -i aws
```

```bash
# Who am I, and what can I do
aws sts get-caller-identity
aws configure list
aws sts get-session-token
```

```bash
# Enumerate, in this order
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies
aws iam get-policy --policy-arn <arn>
aws s3 ls
aws s3api list-buckets
aws sts enumerate-mfa-devices
```

```bash
# Find the over-permissive attachment
aws iam list-attached-user-policies --username <user>
aws iam list-role-policies --role-name <role>
aws iam get-user-policy --user-name <user> --policy-name <policy>
```

```bash
# The policies worth flagging. Both are over-permissive in a way that
# almost always means a real finding.
AdministratorAccess
# or a custom policy containing
"Effect": "Allow", "Action": "*", "Resource": "*"
```

```bash
# Public S3. Unauthenticated, so no credentials needed.
aws s3 ls s3://<bucket> --no-sign-request
aws s3 cp s3://<bucket> ./ --recursive --no-sign-request
curl -s https://<bucket>.s3.amazonaws.com/
curl -s https://s3.amazonaws.com/<bucket>
```

```bash
# The realistic public-exposure pattern
# 1. Block Public Access is OFF on the account
aws s3api get-public-access-block --bucket <bucket>
# 2. The bucket policy allows s3:GetObject from *
aws s3api get-bucket-policy --bucket <bucket>
# 3. The ACL is public-read
aws s3api get-bucket-acl --bucket <bucket>
```

```bash
# Other services with the same shape of exposure
aws ec2 describe-instances
aws lambda list-functions
aws lambda get-function --function-name <name>
aws ssm describe-instance-information       # the one that leaks hostnames broadly
aws secretsmanager list-secrets
```

```bash
# Enumerate a large account properly, from a local copy
pip install pacu
pacu iam --download
pacu sts get-user
pacu s3 --enum
# Recon, on the hostnames AWS knows about
aws ssm describe-instance-information | grep -i "Name\|PrivateIp"
```

```bash
# The tool that finds relationships
# CloudMapper, Roark, and aws-cassandra all do this
# The point is privilege paths, the same graph idea as BloodHound
```

---

## Azure

```bash
# Credentials
env | grep -i "azure\|arm_\|subscription"
cat ~/.azure/msal_token_cache.json
cat ~/.azure/azureProfile.json
az login --service-principal -u '<app-id>' -p '<secret>' --tenant '<tenant>'
az account show
az ad user list --all
```

```bash
# The important distinction
# A subscription is a boundary. Resources in a different subscription are
# a different engagement, and cross-subscription access is itself a finding.
az account list
az account list-locations
az role assignment list --all
az role definition list --name Contributor
```

```bash
# Enumerate
az vm list -o table
az storage account list -o table
az webapp list -o table
az functionapp list -o table
az keyvault list -o table
az aks list -o table
az sql server list -o table
```

```bash
# Managed identity, and the reason metadata matters here
# A VM with a system-assigned identity hands a token to anything that can
# reach the metadata service. Check whether it has roles attached.
az vm identity show -g <resource-group> -n <vm>
az role assignment list --assignee <principal-id>
```

```bash
# Azure Functions, where the credentials usually live
az functionapp function list -g <rg> -n <app>
# Function apps are frequently reachable unauthenticated, and function keys
# are often committed. Check the app settings.
az functionapp config appsettings list -g <rg> -n <app> -o table
```

```bash
# Key vaults, and the logic around them
az keyvault list
az keyvault secret list --vault-name <vault>
az keyvault key list --vault-name <vault>
# Private endpoint and network ACLs are the controls worth testing
az keyvault show -n <vault> --query networkAcls
az keyvault show -n <vault> --query accessPolicy
```

```bash
# Storage accounts, and the classic SAS URL leak
az storage account list
az storage account show-connection-string -n <account>
# A connection string in a public repo is a full finding
az storage blob list --account-name <account> --container-name <container> -s <sas>
```

```bash
# OAuth and app registrations
az ad app list
az ad app permission list --id <app-id> --all
# Over-broad Graph API permissions on an app registration is very common
az ad sp list --all
```

---

## GCP

```bash
# Credentials
gcloud auth list
gcloud config list
cat ~/.config/gcloud/credentials.db
env | grep -i "google\|gcp\|gcloud"
```

```bash
# Service account keys, the thing to look for everywhere
find / -name "*.json" 2>/dev/null | xargs grep -l "private_key" 2>/dev/null
# A service account key committed to a repository is a common and serious finding
```

```bash
# Enumerate
gcloud projects list
gcloud compute instances list
gcloud storage ls
gcloud container clusters list
gcloud functions list
gcloud iam service-accounts list
```

```bash
# IAM, which is a flat policy attached at five levels.
# Find who has what at each level.
gcloud projects get-iam-policy <project>
gcloud storage buckets get-iam-policy gs://<bucket>
gcloud compute instances get-iam-policy <instance> --zone <zone>
# Owner, Editor, and Viewer on a project is the finding.
```

```bash
# The scopes to check on every instance. Over-broad scopes matter more
# than the identity, because the scope is what the token can actually do.
gcloud compute instances describe <instance> --zone <zone> --format="value(scopes)"
# storage.readonly is fine. cloud-platform is not.
```

```bash
# Metadata
gcloud compute instances describe <instance> --zone <zone> --format="value(serviceAccounts)"
```

---

## Containers

```bash
# Am I in one?
cat /proc/1/cgroup
ls -la /.dockerenv 2>/dev/null
cat /proc/self/status | grep -i cap
mount | grep -i "docker\|overlay"
hostname                                     # a container id is a good tell
```

```bash
# A writable host mount is root on the host
mount | grep -w rw
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -i rw
```

```bash
# The Docker socket, which is the common one
ls -la /var/run/docker.sock
# If it is there, talk to it and you are root on the host
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock images
```

```bash
# Capabilities, which is how a container escapes
capsh --print
grep Cap /proc/self/status
# cap_sys_admin is close to full root. cap_sys_ptrace lets you read other
# containers in the same namespace. cap_dac_read_search reads any file.
```

```bash
# Namespace and cgroup clues
ls -la /proc/1/ns/
cat /proc/1/environ
cat /proc/self/mountinfo | head
```

```bash
# Escape by abusing a privileged mount, when one exists
nsenter -t 1 -m -u -n -i sh
```

```bash
# Kubernetes service account, present in every pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

---

## Kubernetes

```bash
# The client, from inside a pod if kubectl is absent
export KUBERNETES_SERVICE_HOST=10.0.0.1
export KUBERNETES_SERVICE_PORT=443
# /var/run/secrets/kubernetes.io/serviceaccount/ca.crt is the CA to trust

# What can this token do? This is the first question every time.
kubectl auth can-i --list
kubectl auth can-i get secrets
kubectl auth can-i --namespace <ns> list pods
```

```bash
# Read the API
kubectl get pods -A
kubectl get secrets -A
kubectl get cm -A                      # configmaps, frequently full of secrets
kubectl describe pod <pod>            # env vars and mounted config
```

```bash
# A privileged pod is a host compromise
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'
# hostPID, hostNetwork, and privileged capabilities are the same problem
```

```bash
# Read the secrets in a namespace you can reach
kubectl get secrets -A -o json | jq -r '.items[] | .data | keys[]' | while read -r k; do
  kubectl get secret <name> -n <ns> -o jsonpath="{.data.$k}" | base64 -d; echo
done
```

```bash
# The API server, when it is reachable unauthenticated. Usually not, but always check.
curl -sk https://<apiserver>:6443/api
curl -sk https://<apiserver>:6443/api/v1/pods
curl -sk https://<apiserver>:10250/pods            # kubelet, often more open
curl -sk https://<kubelet>:10255/pods
```

```bash
# Exposed dashboards and the etcd backup habit
curl -sk https://<host>:30000/
curl -sk https://<host>:6443/version
# etcd holds every secret in the cluster. If a backup or a listener is exposed,
# that is a total compromise and it should be reported as critical.
```

```bash
# Misconfigurations worth checking
# RBAC wildcards
kubectl auth can-i '*' '*'
# HostPath mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.name'
# Service account automount, which is why pods have tokens they do not need
```

---

## Cloud-specific bug classes

| Finding | How to test |
|---|---|
| Public storage bucket | `--no-sign-request` requests, or the equivalent in Azure and GCP |
| Over-permissive IAM | Enumerate, look for `*` actions on `*` resources |
| Metadata reachable from the internet | Try the endpoint from outside. It should never answer |
| SSRF to metadata | Prove reachability, then stop |
| Leaked keys in a repository | History scan, and CI logs |
| Over-scoped instance | Read the instance scopes or roles |
| Public Kubernetes API | `curl -sk` unauthenticated against 6443 |
| Container escape | Privileged pods, capabilities, writable host mounts |
| Cross-subscription access | Check which subscriptions the identity spans |
| Public CI/CD | The pipeline runs in the same cloud, so its role is often the finding |

The last one is worth stating plainly. The most common real cloud compromise is
not a broken bucket. It is a build pipeline with a role attached, a webhook that
can modify the pipeline, and a public repository where someone committed a
credential last year.

---

## Reporting

Cloud findings need the same discipline as everything else, with two additions.

**Map the blast radius, not just the issue.** "This IAM policy allows
`s3:*` on `*`" is a finding. "This policy allows `s3:*` on `*`, which means
anyone who can assume this role can read or overwrite every object in every
bucket in the account, including the backups bucket that holds the database
snapshots" is a finding that gets fixed immediately.

**State what you did not do.** If you proved the metadata service is reachable
and deliberately did not retrieve the credentials, say so explicitly. The client
needs to know the exposure exists, and they need to know the extent of your
access, for their own compliance and for their decision about rotation.

**Never put live cloud credentials in a report**, not even redacted ones you
copied. Reference them by the path and the last four characters, and offer
rotated sample values.

```bash
# If you did use credentials during the engagement, and you should
aws configure list
gcloud auth list
az account show
# Revoke everything at the end. An assessment that leaves access behind is
# an assessment that has created the breach it was paid to look for.
```
