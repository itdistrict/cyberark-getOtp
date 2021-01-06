# cyberark getOTP
Time-base One-Time Password Algorithm (RFC 6238) with CyberArk integration of seed as secret retrieval

This is an implementation of the RFC 6238 Time-Based One-Time Password Algorithm draft based upon the HMAC-based One-Time Password (HOTP) algorithm (RFC 4226). This is a time based variant of the HOTP algorithm providing short-lived OTP values.

Credits for the HOTP powershell implementation goes to Jon Friesen and his provided TOTP powershell function https://gist.github.com/jonfriesen/234c7471c3e3199f97d5

## examples
Calculate OTP from a CyberArk Account (Default Auth Method LDAP, )

```powershell
.\CyberArk-GetOTP.ps1 -AccountSearch "root-mfa,1.1.1.1&filter=safeName eq AWS_ROOT"
```

Calculate OTP from a Seed directly (Default Digits = 6, Time Step Interval = 30s)
```powershell
.\CyberArk-GetOTP.ps1 -OTPOnly -Seed "JBSWY3DPEHPK3PXP"
```
