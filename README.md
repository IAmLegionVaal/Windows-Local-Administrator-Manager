# Windows Local Administrator Manager

A production-focused, idempotent PowerShell utility that creates or updates a local Windows administrator account without embedding credentials in the repository.

## What it does

- Creates the requested local account when it does not exist.
- Resets the password when the account already exists.
- Enables the account.
- Ensures the account never expires.
- Optionally configures the password not to expire.
- Optionally prevents the user from changing the password.
- Adds the account to the built-in local Administrators group using SID `S-1-5-32-544`, so localized Windows group names are supported.
- Verifies that the account is enabled and has administrator membership.
- Writes an operational log without recording the password.
- Returns RMM-friendly exit codes.
- Refuses to run on domain controllers to avoid accidentally modifying domain accounts.

> Administrator membership grants local administrative rights. Windows UAC still applies to interactive sessions and launched processes.

## Requirements

- Windows 10, Windows 11, or Windows Server with a local SAM database.
- Windows PowerShell 5.1 or a compatible PowerShell version on Windows.
- An elevated PowerShell session or execution as `SYSTEM` through an RMM.
- A password that satisfies the endpoint's active local or domain password policy.

## Download

```powershell
git clone https://github.com/IAmLegionVaal/Windows-Local-Administrator-Manager.git
cd Windows-Local-Administrator-Manager
```

## Quick start

Run PowerShell as Administrator. The script securely prompts for the desired password:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Set-LocalAdministrator.ps1 -Username 'SupportAdmin' -PasswordNeverExpires
```

The default username is `SupportAdmin`, so this also works:

```powershell
.\Set-LocalAdministrator.ps1 -PasswordNeverExpires
```

## Supply a SecureString

```powershell
$Password = Read-Host 'Enter the desired password' -AsSecureString

.\Set-LocalAdministrator.ps1 `
    -Username 'SupportAdmin' `
    -Password $Password `
    -PasswordNeverExpires `
    -UserCannotChangePassword
```

## Unattended RMM execution

Inject the password from the RMM's protected secret or custom-field mechanism into the process environment variable `LOCAL_ADMIN_PASSWORD`, then run:

```powershell
.\Set-LocalAdministrator.ps1 `
    -Username 'SupportAdmin' `
    -PasswordNeverExpires `
    -UserCannotChangePassword
```

The script reads `LOCAL_ADMIN_PASSWORD` and removes it from the current process environment immediately after converting it to a `SecureString`.

A wrapper can map an RMM-provided secure variable to the expected environment variable:

```powershell
$env:LOCAL_ADMIN_PASSWORD = $RmmProvidedSecret

try {
    & .\Set-LocalAdministrator.ps1 `
        -Username 'SupportAdmin' `
        -PasswordNeverExpires `
        -UserCannotChangePassword

    exit $LASTEXITCODE
}
finally {
    Remove-Item Env:\LOCAL_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
```

Do not commit a real password into this repository or paste one directly into a reusable RMM script.

## Parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `Username` | `SupportAdmin` | Local account to create or update. |
| `Password` | None | Password supplied as a `SecureString`. |
| `PasswordEnvironmentVariable` | `LOCAL_ADMIN_PASSWORD` | Process environment variable used during unattended execution. |
| `Description` | `Managed local administrator account` | Local account description. |
| `PasswordNeverExpires` | Not changed for existing users | Sets the password not to expire. New users default to normal password-expiration behavior unless supplied. |
| `UserCannotChangePassword` | Not changed for existing users | Prevents the account from changing its password. |
| `LogPath` | `%ProgramData%\LocalAdminManager\LocalAdminManager.log` | Operational log location. |

To explicitly disable a switch-based setting on an existing account:

```powershell
.\Set-LocalAdministrator.ps1 `
    -Username 'SupportAdmin' `
    -PasswordNeverExpires:$false `
    -UserCannotChangePassword:$false
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Account successfully created or updated and verified. |
| `1` | General processing failure. |
| `2` | Script was not elevated. |
| `3` | Password was unavailable or empty. |
| `4` | Unsupported operating system or domain controller. |

## Logging

Default log path:

```text
C:\ProgramData\LocalAdminManager\LocalAdminManager.log
```

The username and operation status are logged. Password values are never logged.

## Security guidance

A shared static local administrator password creates lateral-movement risk if one endpoint is compromised. For managed production environments, prefer Windows LAPS or a privileged-access platform that rotates unique passwords per device.

When a static credential is operationally required:

- Store it in the RMM's protected secret store.
- Restrict script and custom-field access using least privilege.
- Rotate it regularly.
- Monitor local administrator group changes.
- Avoid passing plaintext passwords directly on the command line because command history, process telemetry, and RMM logs may capture them.

## License

Released under the [MIT License](LICENSE).
