#requires -version 5.1

<#
.SYNOPSIS
    Creates or updates a local Windows administrator account.

.DESCRIPTION
    Idempotently creates or updates a local user, resets its password, enables
    the account, configures password options, and ensures membership in the
    built-in local Administrators group.

    The password is accepted as a SecureString, read from a configurable
    process environment variable, or requested through a secure prompt.
    Passwords are never written to the log.

.PARAMETER Username
    Local account name to create or update.

.PARAMETER Password
    Password supplied as a SecureString. When omitted, the script checks the
    environment variable specified by PasswordEnvironmentVariable and then
    falls back to a secure interactive prompt.

.PARAMETER PasswordEnvironmentVariable
    Name of the process environment variable containing the password.
    Defaults to LOCAL_ADMIN_PASSWORD.

.PARAMETER Description
    Description assigned to the local account.

.PARAMETER PasswordNeverExpires
    Configures the local account password not to expire.

.PARAMETER UserCannotChangePassword
    Prevents the local user from changing the password.

.PARAMETER LogPath
    Path to the operational log. Passwords are never logged.

.EXAMPLE
    .\Set-LocalAdministrator.ps1 -Username 'SupportAdmin' -PasswordNeverExpires

.EXAMPLE
    $Password = Read-Host 'Enter password' -AsSecureString
    .\Set-LocalAdministrator.ps1 -Username 'SupportAdmin' -Password $Password

.EXAMPLE
    $env:LOCAL_ADMIN_PASSWORD = 'Use-A-Secret-From-Your-RMM'
    .\Set-LocalAdministrator.ps1 -Username 'SupportAdmin' -PasswordNeverExpires

.NOTES
    Version: 1.0.0
    Author: Dewald Pretorius (IAmLegionVaal)
    Must run from an elevated PowerShell session or as Local System.

.EXITCODES
    0 = Success
    1 = General failure
    2 = Not elevated
    3 = Password unavailable or empty
    4 = Unsupported operating system
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 20)]
    [ValidatePattern('^[^\\/:*?"<>|]+$')]
    [string]$Username = 'SupportAdmin',

    [Parameter()]
    [System.Security.SecureString]$Password,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PasswordEnvironmentVariable = 'LOCAL_ADMIN_PASSWORD',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Description = 'Managed local administrator account',

    [Parameter()]
    [switch]$PasswordNeverExpires,

    [Parameter()]
    [switch]$UserCannotChangePassword,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "$env:ProgramData\LocalAdminManager\LocalAdminManager.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:ExitCode = 1
$script:ResolvedPassword = $null
$script:PasswordWasBound = $PSBoundParameters.ContainsKey('Password')
$script:PasswordNeverExpiresWasBound = $PSBoundParameters.ContainsKey('PasswordNeverExpires')
$script:UserCannotChangePasswordWasBound = $PSBoundParameters.ContainsKey('UserCannotChangePassword')

function Write-OperationalLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry = '[{0}] [{1}] {2}' -f $Timestamp, $Level, $Message
    Write-Output $Entry

    try {
        $ParentDirectory = Split-Path -Path $LogPath -Parent

        if ($ParentDirectory -and -not (Test-Path -LiteralPath $ParentDirectory)) {
            New-Item -Path $ParentDirectory -ItemType Directory -Force | Out-Null
        }

        Add-Content -LiteralPath $LogPath -Value $Entry -Encoding UTF8
    }
    catch {
        Write-Warning "Unable to write to log file '$LogPath': $($_.Exception.Message)"
    }
}

function Test-IsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]::new($Identity)

    return $Principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Resolve-AccountPassword {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param()

    if ($script:PasswordWasBound) {
        return $Password
    }

    $EnvironmentPassword = [Environment]::GetEnvironmentVariable(
        $PasswordEnvironmentVariable,
        [EnvironmentVariableTarget]::Process
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvironmentPassword)) {
        try {
            return ConvertTo-SecureString -String $EnvironmentPassword -AsPlainText -Force
        }
        finally {
            [Environment]::SetEnvironmentVariable(
                $PasswordEnvironmentVariable,
                $null,
                [EnvironmentVariableTarget]::Process
            )
            $EnvironmentPassword = $null
        }
    }

    if (-not [Environment]::UserInteractive) {
        throw "No password was supplied. Pass -Password or set the process environment variable '$PasswordEnvironmentVariable'."
    }

    return Read-Host -Prompt "Enter the password for local account '$Username'" -AsSecureString
}

function Test-SecureStringHasValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Security.SecureString]$SecureValue
    )

    return $SecureValue.Length -gt 0
}

function Invoke-WithPlainTextPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.SecureString]$SecurePassword,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $Bstr = [IntPtr]::Zero
    $PlainTextPassword = $null

    try {
        $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        & $Action $PlainTextPassword
    }
    finally {
        $PlainTextPassword = $null

        if ($Bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        }
    }
}

try {
    if ($env:OS -ne 'Windows_NT') {
        $script:ExitCode = 4
        throw 'This script supports Windows only.'
    }

    if (-not (Test-IsElevated)) {
        $script:ExitCode = 2
        throw 'The script must run as Administrator or Local System.'
    }

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

    if ([int]$ComputerSystem.DomainRole -ge 4) {
        $script:ExitCode = 4
        throw 'Domain controllers do not have a local SAM database. This script intentionally refuses to create or modify domain accounts.'
    }

    try {
        $script:ResolvedPassword = Resolve-AccountPassword
    }
    catch {
        $script:ExitCode = 3
        throw
    }

    if ($null -eq $script:ResolvedPassword -or -not (Test-SecureStringHasValue -SecureValue $script:ResolvedPassword)) {
        $script:ExitCode = 3
        throw 'The supplied password is empty.'
    }

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
    $IdentityType = [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName
    $SidIdentityType = [System.DirectoryServices.AccountManagement.IdentityType]::Sid

    $Context = $null
    $LocalUser = $null
    $Context = [System.DirectoryServices.AccountManagement.PrincipalContext]::new($ContextType)

    try {
        $LocalUser = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
            $Context,
            $IdentityType,
            $Username
        )

        $WasCreated = $false

        if ($null -eq $LocalUser) {
            Write-OperationalLog -Message "Creating local account '$Username'."

            $LocalUser = [System.DirectoryServices.AccountManagement.UserPrincipal]::new($Context)
            $LocalUser.SamAccountName = $Username
            $LocalUser.Name = $Username
            $WasCreated = $true
        }
        else {
            Write-OperationalLog -Message "Local account '$Username' already exists; resetting its password and configuration."
        }

        Invoke-WithPlainTextPassword -SecurePassword $script:ResolvedPassword -Action {
            param([string]$PlainText)
            $LocalUser.SetPassword($PlainText)
        }

        $LocalUser.Description = $Description
        $LocalUser.Enabled = $true

        if ($WasCreated -or $script:PasswordNeverExpiresWasBound) {
            $LocalUser.PasswordNeverExpires = $PasswordNeverExpires.IsPresent
        }

        if ($WasCreated -or $script:UserCannotChangePasswordWasBound) {
            $LocalUser.UserCannotChangePassword = $UserCannotChangePassword.IsPresent
        }

        $LocalUser.AccountExpirationDate = $null
        $LocalUser.Save()

        $AdministratorsGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(
            $Context,
            $SidIdentityType,
            'S-1-5-32-544'
        )

        if ($null -eq $AdministratorsGroup) {
            throw 'Unable to resolve the built-in local Administrators group by SID S-1-5-32-544.'
        }

        try {
            $AlreadyMember = $LocalUser.IsMemberOf($AdministratorsGroup)

            if (-not $AlreadyMember) {
                Write-OperationalLog -Message "Adding '$Username' to the local Administrators group."
                $AdministratorsGroup.Members.Add($LocalUser)
                $AdministratorsGroup.Save()
            }
            else {
                Write-OperationalLog -Message "'$Username' is already a member of the local Administrators group."
            }

            $VerifiedUser = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
                $Context,
                $IdentityType,
                $Username
            )

            if ($null -eq $VerifiedUser) {
                throw "Verification failed: local account '$Username' could not be found after processing."
            }

            try {
                if ($VerifiedUser.Enabled -ne $true) {
                    throw "Verification failed: local account '$Username' is disabled."
                }

                $MembershipVerified = $VerifiedUser.IsMemberOf($AdministratorsGroup)

                if (-not $MembershipVerified) {
                    throw "Verification failed: '$Username' is not a member of the local Administrators group."
                }
            }
            finally {
                $VerifiedUser.Dispose()
            }
        }
        finally {
            $AdministratorsGroup.Dispose()
        }

        $ActionText = if ($WasCreated) { 'created' } else { 'updated' }
        Write-OperationalLog -Message "Successfully $ActionText and verified local administrator '$Username'."
        $script:ExitCode = 0
    }
    finally {
        if ($null -ne $LocalUser) {
            $LocalUser.Dispose()
        }

        if ($null -ne $Context) {
            $Context.Dispose()
        }
    }
}
catch {
    Write-OperationalLog -Level 'ERROR' -Message $_.Exception.Message
}
finally {
    $script:ResolvedPassword = $null
}

exit $script:ExitCode
