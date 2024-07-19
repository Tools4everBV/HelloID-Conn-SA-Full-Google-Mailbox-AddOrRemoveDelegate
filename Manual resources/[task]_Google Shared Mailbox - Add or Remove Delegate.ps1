# Variables configured in form
$mailbox = $form.mailbox
$user = $form.user
$action = $form.action

# Fixed values
$scopes = @(
    "https://www.googleapis.com/auth/gmail.settings.sharing"
)

# Global variables
$p12CertificateBase64 = $GoogleP12CertificateBase64
$p12CertificatePassword = $GoogleP12CertificatePassword
$serviceAccountEmail = $GoogleServiceAccountEmail
$userId = $form.mailbox.primaryEmail # Email address of mailbox to manage delegates for.

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-GoogleError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }

        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + ". Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
                $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject.Exception.Message
            }
        }
            
        Write-Output $httpErrorObj
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.Powershell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

try {
    #region Create access token
    $actionMessage = "creating acess token"

    # Create a JWT (JSON Web Token) header
    $header = @{
        alg = "RS256"
        typ = "JWT"
    } | ConvertTo-Json
    $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

    # Calculate the Unix timestamp for 'exp' and 'iat'
    $now = [Math]::Round((Get-Date (Get-Date).ToUniversalTime() -UFormat "%s"), 0)
    $createDate = $now
    $expiryDate = $createDate + 3540 # Expires in 59 minutes

    # Create a JWT payload
    $payload = [Ordered]@{
        iss   = "$serviceAccountEmail"
        sub   = "$userId"
        scope = "$($scopes -join " ")"
        aud   = "https://www.googleapis.com/oauth2/v4/token"
        exp   = "$expiryDate"
        iat   = "$createDate"
    } | ConvertTo-Json
    $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload))

    # Convert Base64 string to certificate
    $rawP12Certificate = [system.convert]::FromBase64String($p12CertificateBase64)
    $p12Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawP12Certificate, $p12CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

    # Extract the private key from the P12 certificate
    $rsaPrivate = $P12Certificate.PrivateKey
    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

    # Sign the JWT
    $signatureInput = "$base64Header.$base64Payload"
    $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), "SHA256")
    $base64Signature = [System.Convert]::ToBase64String($signature)

    # Create the JWT token
    $jwtToken = "$signatureInput.$base64Signature"

    $createAccessTokenBody = [Ordered]@{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assertion  = $jwtToken
    }

    $createAccessTokenSplatParams = @{
        Uri         = "https://www.googleapis.com/oauth2/v4/token"
        Method      = "POST"
        Body        = $createAccessTokenBody
        ContentType = "application/x-www-form-urlencoded"
        Verbose     = $false
        ErrorAction = "Stop"
    }

    $createAccessTokenResponse = Invoke-RestMethod @createAccessTokenSplatParams

    Write-Verbose "Created access token. Result: $($createAccessTokenResponse | ConvertTo-Json)."
    #endregion Create access token

    #region Create headers
    $actionMessage = "creating headers"

    $headers = @{
        "Authorization" = "Bearer $($createAccessTokenResponse.access_token)"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
    }

    Write-Verbose "Created headers. Result: $($headers | ConvertTo-Json)."
    #endregion Create headers
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage

    Write-Error $auditMessage
}

if ($null -ne $headers) {
    switch ($action) {
        "addUserToMailbox" {
            try {
                #region Add delegate to mailbox
                # Google docs: https://developers.google.com/gmail/api/reference/rest/v1/users.settings.delegates/create
                # Define user object to add as delegate
                $user = @{
                    id          = $user.primaryEmail
                    displayName = $user.fullName
                }
        
                # Define mailbox object to add the delegate to
                $mailbox = @{
                    id          = $mailbox.primaryEmail
                    displayName = $mailbox.fullName
                }
        
                $actionMessage = "adding delegate with displayname [$($user.displayName)] and id [$($user.id)] to mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]"
        
                $addDelegateBody = @{
                    delegateEmail = $user.id
                }
                    
                $addDelegateSplatParams = @{
                    Uri         = "https://gmail.googleapis.com/gmail/v1/users/$($mailbox.id)/settings/delegates"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($addDelegateBody | ConvertTo-Json -Depth 10)
                    ContentType = "application/json; charset=utf-8"
                    Verbose     = $false 
                    ErrorAction = "Stop"
                }
        
                $addDelegateResponse = Invoke-RestMethod @addDelegateSplatParams
        
                Write-Verbose "Added delegate with displayname [$($user.displayName)] and id [$($user.id)] to mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]."
                #endregion Add delegated to mailbox
        
                #region Send auditlog to HelloID
                $actionMessage = "sending auditlog to HelloID"
        
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Google" # optional (free format text) 
                    Message           = "Added user with displayname [$($user.displayName)] and id [$($user.id)] to mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                    TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                }
                Write-Information -Tags "Audit" -MessageData $log
                #endregion Send auditlog to HelloID
            }
            catch {
                $ex = $PSItem
                if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                    $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                    $errorObj = Resolve-GoogleError -ErrorObject $ex
                    $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
                    $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
                }
                else {
                    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                }

                if ($auditMessage -like "*Delegate already exists*") {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
        
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = "Skipped adding user with displayname [$($user.displayName)] and id [$($user.id)] to mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]. Reason: User is already a delegate of the mailbox." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                        TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
                }
                else {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
        
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = $auditMessage # required (free format text)
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                        TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
        
                    Write-Warning $warningMessage
        
                    Write-Error $auditMessage
                }
            }
        }
        "removeUserFromMailbox" {
            try {
                #region Remove delegate from mailbox
                # Google docs: https://developers.google.com/gmail/api/reference/rest/v1/users.settings.delegates/delete
                # Define user object to remove as delegate
                $user = @{
                    id          = $user.primaryEmail
                    displayName = $user.fullName
                }
                # Define mailbox object to remove the delegate from
                $mailbox = @{
                    id          = $mailbox.primaryEmail
                    displayName = $mailbox.fullName
                }
    
                $actionMessage = "removing delegate with displayname [$($user.displayName)] and id [$($user.id)] from mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]"
                
                $removeDelegateSplatParams = @{
                    Uri         = "https://gmail.googleapis.com/gmail/v1/users/$($mailbox.id)/settings/delegates/$($user.id)"
                    Headers     = $headers
                    Method      = "DELETE"
                    Verbose     = $false 
                    ErrorAction = "Stop"
                }
    
                $removeDelegateResponse = Invoke-RestMethod @removeDelegateSplatParams
    
                Write-Verbose "Removed delegate with displayname [$($user.displayName)] and id [$($user.id)] from mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]."
                #endregion Remove delegate from mailbox
    
                #region Send auditlog to HelloID
                $actionMessage = "sending auditlog to HelloID"
    
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Google" # optional (free format text) 
                    Message           = "Removed user with displayname [$($user.displayName)] and id [$($user.id)] from mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                    TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                }
                Write-Information -Tags "Audit" -MessageData $log
                #endregion Send auditlog to HelloID
            }
            catch {
                $ex = $PSItem
                if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                    $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                    $errorObj = Resolve-GoogleError -ErrorObject $ex
                    $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
                    $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
                }
                else {
                    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                }
                Write-Warning $warningMessage
                if ($auditMessage -like "*Invalid delegate*") {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
    
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = "Skipped removing user with displayname [$($user.displayName)] and id [$($user.id)] from mailbox with displayName [$($mailbox.displayName)] and id [$($mailbox.id)]. Reason: User is already no longer a delegate." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                        TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
                }
                else {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
    
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = $auditMessage # required (free format text)
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$mailbox.displayName # optional (free format text)
                        TargetIdentifier  = [string]$mailbox.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
    
                    Write-Warning $warningMessage
    
                    Write-Error $auditMessage
                }
            }
        }
    }
}
