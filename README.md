# Cyberark-getOtp
Time-base One-Time Password Algorithm (RFC 6238) with CyberArk integration of seed as secret retrieval

This is an implementation of the RFC 6238 Time-Based One-Time Password Algorithm draft based upon the HMAC-based One-Time Password (HOTP) algorithm (RFC 4226). This is a time based variant of the HOTP algorithm providing short-lived OTP values.

Credits for the HOTP powershell implementation goes to Jon Friesen and his provided TOTP powershell function https://gist.github.com/jonfriesen/234c7471c3e3199f97d5

## Parameters
Calculate OTP from a CyberArk Account (Default Auth Method LDAP, )

### CyberArk
Default Parameter set

#### -AccountSearch
Search keywords and filter to specify an account which has the seed secret and given platform with Time-Step and Digits parameters (optional)

See also:
https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____1

#### -AuthMethod
RADIUS, LDAP or CyberArk
Default: LDAP

#### -PvwaUrl
Pvwa BaseUrl and Applicationlike: "https://pvwa.acme.com/PasswordVault"

### -OTPOnly
Generate a TOTP based on a given seed without any CyberArk connection/retrieval

#### -Secret
BASE32 seed

#### -TimeStep
Time step windows in seconds
Default: 30

#### -Digits
Number of digits of the calculated OTP
Default: 6

## Examples
Calculate OTP from a CyberArk Account (Default Auth Method LDAP, )

```powershell
.\CyberArk-GetOTP.ps1 -AccountSearch "root-mfa,1.1.1.1&filter=safeName eq AWS_ROOT"
```

Calculate OTP from a seed secret directly (Default Digits = 6, Time Step Interval = 30s)
```powershell
.\CyberArk-GetOTP.ps1 -OTPOnly -Secret "JBSWY3DPEHPK3PXP"
```
