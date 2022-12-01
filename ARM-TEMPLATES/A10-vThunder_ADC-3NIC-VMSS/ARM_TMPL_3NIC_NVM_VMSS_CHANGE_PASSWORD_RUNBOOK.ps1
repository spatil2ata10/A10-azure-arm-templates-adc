param (
    [Parameter(Mandatory=$True)]
    [String] $vThunderProcessingIP,
    [Parameter(Mandatory=$True)]
    [String] $oldPassword,
    [Parameter(Mandatory=$True)]
    [String] $newPassword
)

# Authenticate with Azure Portal
$vThUsername = Get-AutomationVariable -Name vThUsername

function Get-AuthToken {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .OUTPUTS
        Authorization token
        .DESCRIPTION
        Function to get Authorization token
        AXAPI: /axapi/v3/auth
    #>
    param (
        $baseUrl
    )
    # AXAPI Auth url
    $url = -join($baseUrl, "/auth")
    # AXAPI header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    # AXAPI Auth url json body
    $body = "{
    `n    `"credentials`": {
    `n        `"username`": `"$vThUsername`",
    `n        `"password`": `"$oldPassword`"
    `n    }
    `n}"

    # Invoke Auth url
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $headers -Body $body
    # fetch Authorization token from response
    $authorizationToken = $Response.authresponse.signature
    if ($null -eq $authorizationToken) {
        Write-Error "Falied to get authorization token from AXAPI" -ErrorAction Stop
    }
    return $authorizationToken
}

function ChangedAdminPassword {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function for changing admin password
        AXAPI: /axapi/v3/admin/{admin-user}/password
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    $Url = -join($BaseUrl, "/admin/admin/password")
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    $Headers.Add("Content-Type", "application/json")
    $Body = "{
        `n  `"password`": {
        `n    `"password-in-module`": `"$newPassword`",
        `n    `"encrypted-in-module`": `"Unknown Type: encrypted`"
        `n  }
        `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $Headers -Body $Body
    if ($null -eq $response) {
        Write-Error "Failed to change password"
    } else {
        Write-Host "password has been changed"
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
    $Url = -join($BaseUrl, "/active-partition")
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'GET' -Headers $Headers
    $partition = $response.'active-partition'.'partition-name'

    if ($null -eq $partition) {
        Write-Error "Failed to get partition name"
    } else {
        $Url = -join($BaseUrl, "/write/memory")
        $Headers.Add("Content-Type", "application/json")

        $Body = "{
        `n  `"memory`": {
        `n    `"partition`": `"$partition`"
        `n  }
        `n}"

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $Headers -Body $Body
        if ($null -eq $response) {
            Write-Error "Failed to run write memory command"
        } else {
            Write-Host "Configurations are saved on partition: "$partition
        }
    }
}

$vthunderBaseUrl = -join("https://", $vThunderProcessingIP, "/axapi/v3")
$authorizationToken = Get-AuthToken -baseUrl $vthunderBaseUrl
ChangedAdminPassword -baseUrl $vthunderBaseUrl -authorizationToken $authorizationToken

WriteMemory -baseUrl $vthunderBaseUrl -authorizationToken $authorizationToken
Write-Output "password changed successful"
