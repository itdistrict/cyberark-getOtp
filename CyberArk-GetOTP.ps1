<#
.SYNOPSIS
Time-base One-Time Password Algorithm (RFC 6238) with CyberArk integration of seed as secret retrieval
.DESCRIPTION
This is an implementation of the RFC 6238 Time-Based One-Time Password Algorithm draft based upon the HMAC-based One-Time Password (HOTP) algorithm (RFC 4226). This is a time based variant of the HOTP algorithm providing short-lived OTP values.
.NOTES
Credits for the HOTP powershell implementation goes to Jon Friesen and his provided TOTP powershell function https://gist.github.com/jonfriesen/234c7471c3e3199f97d5
.EXAMPLE
Calculate OTP from a CyberArk Account (Default Auth Method LDAP, )
.\CyberArk-GetOTP.ps1 -AccountSearch "root-mfa,1.1.1.1&filter=safeName eq AWS_ROOT"
.EXAMPLE
Enter the seed secret securely and calculate the OTP directly (Default Digits = 6, Time Step Interval = 30s)
.\CyberArk-GetOTP.ps1 -OTPOnly
.EXAMPLE
Calculate OTP from a seed secret directly (Default Digits = 6, Time Step Interval = 30s)
.\CyberArk-GetOTP.ps1 -OTPOnly -Secret "JBSWY3DPEHPK3PXP"

#>
[CmdletBinding(DefaultParametersetName = "CyberArk")]
param
(
    [Parameter(ParameterSetName = "OTPOnly", Mandatory = $true)]
    [switch]$OTPOnly,

    [Parameter(ParameterSetName = "OTPOnly")]
    [securestring]$Secret,

    [Parameter(ParameterSetName = "OTPOnly", Mandatory = $false)]
    [String]$TimeStep = "30",

    [Parameter(ParameterSetName = "OTPOnly", Mandatory = $false)]
    [String]$Digits = "6",

    [Parameter(ParameterSetName = "CyberArk", Mandatory = $true)]
    [String]$AccountSearch,

    [Parameter(ParameterSetName = "CyberArk", Mandatory = $false)]
    [ValidateSet("LDAP", "CyberArk", "RADIUS")]
    [String]$AuthMethod = "LDAP",
    
    [Parameter(ParameterSetName = "CyberArk", Mandatory = $false)]
    [String]$PvwaUrl = "https://pvwa.acme.com/PasswordVault",
    
    [Parameter()]
    [bool]$CopyToClipboard = $true
)

function Get-Otp() {
    param(
        [Parameter(Mandatory = $true)]$secret,
        $digits = 6,
        $timeStep = 30
    )
    
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($secret.ToUpper())))
    $timeBytes = Get-TimeByteArray $timeStep
    $randHash = $hmac.ComputeHash($timeBytes)

    $offset = $randhash[($randHash.Length - 1)] -band 0xf
    $fullOTP = ($randhash[$offset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($randHash[$offset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $digits)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $digits)
    return $otp
}

function Get-TimeByteArray($timeStep) {
    $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $unixTime = [Convert]::ToInt64([Math]::Floor($span / $timeStep))
    $byteArray = [BitConverter]::GetBytes($unixTime)
    [array]::Reverse($byteArray)
    return $byteArray
}

function Convert-HexToByteArray($hexString) {
    $byteArray = New-Object byte[] ($hexString.Length / 2)
    For ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $byteArray[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    return $byteArray
}

function Convert-Base32ToHex($base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";

    for ($i = 0; $i -lt $base32.Length; $i++) {
        $val = $base32chars.IndexOf($base32.Chars($i));
        $binary = [Convert]::ToString($val, 2)
        $staticLen = 5
        $padder = '0'
        $bits += Add-LeftPad $binary.ToString()  $staticLen  $padder
    }

    for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
        $chunk = $bits.Substring($i, 4)
        $intChunk = [Convert]::ToInt32($chunk, 2)
        $hexChunk = Convert-IntToHex($intChunk)
        $hex = $hex + $hexChunk
    }

    return $hex;

}

function Convert-IntToHex([int]$num) {
    return ('{0:x}' -f $num)
}

function Add-LeftPad($str, $len, $pad) {
    if (($len + 1) -ge $str.Length) {
        while (($len - 1) -ge $str.Length) {
            $str = ($pad + $str)
        }
    }
    return $str;
}

# Return calculated OTP
if ($OTPOnly) {
    if (!$Secret) { 
        $Secret = Read-Host -assecurestring "Please enter the Seed/Secret to calculate the OTP:" 
    }
    $Seed = [System.Net.NetworkCredential]::new("", $Secret).Password
    $OTP = Get-Otp $Seed $Digits $TimeStep
    Write-Host "Next OTP with time-step $TimeStep and digits-size $Digits`:"
    Write-Host -ForegroundColor Cyan $OTP
    If ($CopyToClipboard) { 
        Set-Clipboard -Value $OTP
        Write-Host -ForegroundColor Green "`nCopied to clipboard!" 
    }
    exit
}

# PowerShell Settings
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
if ($psCertValidation) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

$ErrorActionPreference = "Stop"

# Get API creds
$caCredentials = Get-Credential -Message "Please enter your $AuthMethod Username and Password" 

# Logon
$header = @{ }
$header.Add('Content-type', 'application/json') 
$logonURL = $PvwaUrl + '/api/auth/' + $AuthMethod + '/Logon'
$logonData = @{ username = $caCredentials.GetNetworkCredential().UserName; password = $caCredentials.GetNetworkCredential().Password; concurrentSession = $true; } | ConvertTo-Json
try {
    $logonResult = $( Invoke-WebRequest -Uri $logonURL -Headers $header -Method Post -UseBasicParsing -Body $logonData ).content | ConvertFrom-Json 
} 
catch { 
    Write-Error "Login failed. Did you define the right credentials to login to CyberArk via $AuthMethod ?"
}
$header.Add('Authorization' , $logonResult) 

# Get Account
$accountURL = $PvwaUrl + "/api/Accounts?search=$AccountSearch"
$accountsResult = $(Invoke-WebRequest -Uri $accountURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json
if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
    if ($accountsResult.value.Length -gt 1) {
        Write-Warning "Multiple accounts found ($accountsResult.value.Length) for search $AccountSearch - will identify MFA parameters`n"
        foreach ($accountValue in $accountsResult.value) {
            if ( ([string]::IsNullOrEmpty($accountValue.platformAccountProperties.Duration)) -or ([string]::IsNullOrEmpty($accountValue.platformAccountProperties.Timeout)) ) {
                continue 
            }
            else {
                $account = $accountValue
                break
            }
        }
    }
    else {
        $account = $accountsResult.value[0]
    }
}
else {
    Write-Error "No MFA account not found"
}

# Get Account Details
if (![string]::IsNullOrEmpty($account.platformAccountProperties.Duration)) { $timeStep = $account.platformAccountProperties.Duration }
if (![string]::IsNullOrEmpty($account.platformAccountProperties.Timeout)) { $digits = $account.platformAccountProperties.Timeout }

# Get Secret 
$secretUrl = $PvwaUrl + "/api/Accounts/$($account.id)/Password/Retrieve"
$seed = $(Invoke-WebRequest -Uri $secretUrl -Headers $header -Method Post -UseBasicParsing).content | ConvertFrom-Json

# Calculate OTP
$OTP = Get-Otp $seed $digits $timeStep
Write-Host "Next OTP for $($account.name) with time-step $timeStep and digits-size $digits`:"
Write-Host -ForegroundColor Cyan $OTP

If ($CopyToClipboard) { 
    Set-Clipboard -Value $OTP
    Write-Host -ForegroundColor Green "`nCopied to clipboard!" 
}

# Logoff
try { Invoke-WebRequest -Uri $( $baseURL + '/api/auth/Logoff') -Headers $header -UseBasicParsing -Method Post | Out-Null } catch { }
