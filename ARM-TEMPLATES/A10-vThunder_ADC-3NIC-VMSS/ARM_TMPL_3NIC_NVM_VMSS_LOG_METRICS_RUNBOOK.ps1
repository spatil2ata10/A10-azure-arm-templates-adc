param (
    [Parameter(Mandatory=$True)]
    [String] $vThunderProcessingIP,
    [Parameter(Mandatory=$True)]
    [String] $vThunderResourceId
)

$azureLogMetrics = Get-AutomationVariable -Name azureLogMetricsParam
$azureLogMetrics = $azureLogMetrics | ConvertFrom-Json
$log_action = $azureLogMetrics.log_action
$metrics_action = $azureLogMetrics.metrics_action
$cpu_metrics = $azureLogMetrics.cpu_metrics
$memory_metrics = $azureLogMetrics.memory_metrics
$disk_metrics = $azureLogMetrics.disk_metrics

if (($log_action -eq "disable") -and ($metrics_action -eq "disable")){
    Write-Output "Log Metrics are disable"
    Exit
}

# Get resource config from variables
$azureAutoScaleResources = Get-AutomationVariable -Name azureAutoScaleResources
$azureAutoScaleResources = $azureAutoScaleResources | ConvertFrom-Json

$vThUserName = Get-AutomationVariable -Name vThUserName
$vThPassword = Get-AutomationVariable -Name vThCurrentPassword
$oldPassword = Get-AutomationVariable -Name vThDefaultPassword

if ($null -eq $azureAutoScaleResources) {
    Write-Error "azureAutoScaleResources data is missing." -ErrorAction Stop
}

# Authenticate with Azure Portal
$appId = $azureAutoScaleResources.appId
$secret = Get-AutomationVariable -Name clientSecret
$tenantId = $azureAutoScaleResources.tenantId

$secureStringPwd = $secret | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appId, $secureStringPwd
Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantId

# Get variables
#log analytics workspace id
$workspaceId = Get-AutomationVariable -Name workspaceId
#log analytics shared key
$sharedKey = Get-AutomationVariable -Name sharedKey

#vmss resource Id
$vmssResourceId = Get-AutomationVariable -Name vmssResourceId
#location
$location = $azureAutoScaleResources.location


function Get-AuthToken {
    <#
        .PARAMETER base_url
        Base url of AXAPI
        .DESCRIPTION
        Function to get Authorization token from axapi
        AXAPI: /axapi/v3/auth
    #>
    param (
        $baseUrl,
        $vThPass
    )

    # AXAPI Auth url
    $url = -join($baseUrl, "/auth")
    # AXAPI header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    # AXAPI Auth url json body
    $body = "{
    `n    `"credentials`": {
    `n        `"username`": `"$vThUserName`",
    `n        `"password`": `"$vThPass`"
    `n    }
    `n}"
    $maxRetry = 5
    $currentRetry = 0
    while ($currentRetry -ne $maxRetry) {
        # Invoke Auth url
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $response = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $headers -Body $body
        # fetch Authorization token from response
        $authorizationToken = $response.authresponse.signature
        if ($null -eq $authorizationToken) {
            Write-Error "Retry $currentRetry to get authorization token"
            $currentRetry++
            start-sleep -s 60
        } else {
            break
        }
    }
    if ($null -eq $authorizationToken) {
            Write-Error "Falied to get authorization token from AXAPI" -ErrorAction Stop
    }
    return $authorizationToken
}

function ConfigureLog {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to configure Cloud Services
        AXAPI: /axapi/v3/cloud-services/cloud-provider
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    
    $url = -join($BaseUrl, "/cloud-services/cloud-provider/azure/log")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    $headers.Add("Content-Type", "application/json")

    $body = "{
    `n`"log`":
    `n    {
    `n    `"action`": `"$log_action`",
    `n    `"customer-id`" : `"$workspaceId`",
    `n    `"shared-key`": `"$sharedKey`",
    `n    `"resource-id`": `"$vThunderResourceId`"
    `n    }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

    if ($null -eq $response) {
        Write-Error "Failed to configure log services"
    } else {
        Write-Host "Configured log services"
    }
}

function ConfigureMetrics {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to configure Cloud Services
        AXAPI: /axapi/v3/cloud-services/cloud-provider
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    
    $url = -join($BaseUrl, "/cloud-services/cloud-provider/azure/metrics")
   
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    $headers.Add("Content-Type", "application/json")
    
    $location = $location.ToLower().Replace(" ","")

    $body = "{
    `n`"metrics`": {
    `n        `"action`": `"$metrics_action`",
    `n        `"client-id`": `"$appId`",
    `n        `"tenant-id`": `"$tenantId`",
    `n        `"secret-id`": `"$secret`",
    `n        `"resource-id`": `"$vmssResourceId`",
    `n        `"location`": `"$location`",
    `n        `"cpu`": `"$cpu_metrics`",
    `n        `"disk`": `"$disk_metrics`",
    `n        `"memory`": `"$memory_metrics`"
    `n    }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

    if ($null -eq $response) {
        Write-Error "Failed to configure metrics services"
    } else {
        Write-Host "Configured metrics services"
    }
}

function WriteMemory {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to save configurations on active partition
        AXAPI: /axapi/v3/active-partition
        AXAPI: /axapi/v3/write/memory
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    $Url = -join($BaseUrl, "/write/memory")

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers

}

$vthunderBaseUrl = -join("https://", $vThunderProcessingIP, "/axapi/v3")
# Get Authorization Token
$authorizationToken = Get-AuthToken -baseUrl $vthunderBaseUrl -vThPass $vThPassword

if ($authorizationToken -eq 401){
    $authorizationToken = Get-AuthToken -baseUrl $vthunderBaseUrl -vThPass $oldPassword
}

if ($log_action -eq "enable"){
    Write-Output "Function Configure Log called" 
    ConfigureLog -BaseUrl $vthunderBaseUrl -AuthorizationToken $authorizationToken
}

if ($metrics_action -eq "enable"){
    Write-Output "Function Configure Metrics called" 
    ConfigureMetrics -BaseUrl $vthunderBaseUrl -AuthorizationToken $authorizationToken
}

WriteMemory -BaseUrl $vthunderBaseUrl -AuthorizationToken $authorizationToken
Write-Host "WriteMemory "

Write-Host "apply Cloud-Services"
