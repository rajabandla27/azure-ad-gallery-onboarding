# Test script to find Dropbox Business in Azure AD Gallery
. .\EntraCreds.ps1

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications

$SecureSecret = ConvertTo-SecureString $ApplicationSecret -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $SecureSecret)

Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential -NoWelcome

Write-Host "Searching for Dropbox applications in Azure AD Gallery..." -ForegroundColor Yellow

try {
    # Search for all Dropbox-related applications
    $DropboxApps = Get-MgApplicationTemplate -Filter "contains(displayName,'Dropbox')"
    
    if ($DropboxApps) {
        Write-Host "Found $($DropboxApps.Count) Dropbox-related applications:" -ForegroundColor Green
        foreach ($App in $DropboxApps) {
            Write-Host "  Name: $($App.DisplayName)" -ForegroundColor Cyan
            Write-Host "  ID: $($App.Id)" -ForegroundColor Gray
            Write-Host "  Publisher: $($App.Publisher)" -ForegroundColor Gray
            Write-Host "  Categories: $($App.Categories -join ', ')" -ForegroundColor Gray
            Write-Host "  ---" -ForegroundColor Gray
        }
        
        # Try to find exact "Dropbox Business" match
        $DropboxBusiness = $DropboxApps | Where-Object { $_.DisplayName -eq "Dropbox Business" }
        if ($DropboxBusiness) {
            Write-Host "Found exact match for 'Dropbox Business': $($DropboxBusiness.Id)" -ForegroundColor Green
        } else {
            Write-Host "No exact match for 'Dropbox Business' found" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No Dropbox applications found in gallery" -ForegroundColor Red
    }
} catch {
    Write-Error "Failed to search gallery: $($_.Exception.Message)"
}

Disconnect-MgGraph