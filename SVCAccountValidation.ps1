$Result = @()
$users = Get-ADUser -SearchBase "ou=Service,ou=UserAccounts,dc=nsn-intra,dc=net" -Filter "Enabled -eq '$true'" -Properties *
$users.Count

foreach ($line in $users) {
    $serviceAccount = $line.SamAccountName
    $group = "Deny_Interactive_Logon_ServiceAccounts_A"

    $memberOf = (Get-ADUser $serviceAccount -Properties MemberOf).MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name
    $interactiveLogon = if ($memberOf -contains $group) { "Disabled" } else { "Enabled" }

    $createdOn = ""
    if ($line.whenCreated) {
        $createdOn = [datetime]$line.whenCreated | Get-Date -Format 'dd-MM-yyyy'
    }

    $lastLogon = ""
    if ($line.lastLogonTimestamp) {
        $lastLogon = [datetime]::FromFileTime($line.lastLogonTimestamp).ToString('dd-MM-yyyy')
    }

    $passwordSet = ""
    if ($line.PasswordLastSet -is [datetime]) {
        $passwordSet = $line.PasswordLastSet.ToString('dd-MM-yyyy')
    }

    $ownerStatus = ""
    if ([string]::IsNullOrEmpty($line.EmailAddress)) {
        $ownerDetails = $line.Description
        if (-not [string]::IsNullOrEmpty($ownerDetails)) {
            $ownerAccountPattern = "Owner:\s*([^ ]+@[^ ]+)"
            $ownerAccountMatch = [regex]::Match($ownerDetails, $ownerAccountPattern)
            if ($ownerAccountMatch.Success) {
                $ownerAccount = $ownerAccountMatch.Groups[1].Value
                $ownerAccountStatus = Get-ADUser -Filter "UserPrincipalName -eq '$ownerAccount'" -Properties Enabled -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($ownerAccountStatus) {
                    $ownerAccountSAM = $ownerAccountStatus.samaccountname
                    if ($ownerAccountStatus.Enabled) {
                        $ownerStatus = "Enabled in AD: $ownerAccount ($ownerAccountSAM)"
                    } else {
                        $ownerStatus = "Disabled in AD: $ownerAccount ($ownerAccountSAM)"
                    }
                } else {
                    #Write-Warning "Unable to find the account for the owner: $ownerAccount"
                    $ownerStatus = "Not found in AD: $ownerAccount"
                }
            } else {
                $ownerStatus = "Invalid owner details"
            }
        } else {
            $ownerStatus = "No owners in the Mail/description"
        }
    } else {
        $string = $line.EmailAddress
        $pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        $OwnerEmail = $string | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
        $associatedUser = Get-ADUser -Filter "Userprincipalname -eq '$OwnerEmail'" -Properties *
        $ownerStatus = if ($associatedUser) { if ($associatedUser.Enabled) { "Enabled" } else { "Disabled" } } else { "N/A" }
    }

    $properties = [ordered]@{
        "Service Account"      = $line.Name
        "Enabled"              = $line.Enabled
        "Owner"                 = $line.EmailAddress
        "Owner Status"         = $ownerStatus
        "Interactive logon"    = $interactiveLogon
        "Created on"           = $createdOn
        "Last logon date"      = $lastLogon
        "Last password set"    = $passwordSet
        "Description"          = $line.Description
        "Logon workstations"   = $line.userWorkstations
    }

    $Result += New-Object -TypeName PSObject -Property $properties
}

$Result | Export-Csv -Path .\Desktop\svcAccount_Validation.csv -NoTypeInformation
