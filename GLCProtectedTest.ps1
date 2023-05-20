$base64Script = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($scriptPath))
# Prompt for password
$password = Read-Host -Prompt "Enter the password" -AsSecureString
# Convert password to plain text
$passwordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
# Define expected password
$expectedPassword = "HCLADADMIN"

# Verify the provided password
if ($passwordPlainText -eq $expectedPassword) {
    $scriptPath = "C:\Users\kori\OneDrive - Nokia\Scripts\GLCAutomated - Copy.ps1"
    $decodedScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Script))
    Invoke-Expression -Command $decodedScript
} else {
    # Password is incorrect, exit script or display an error message
    Write-Host "Incorrect password. Script execution aborted."
    exit
}