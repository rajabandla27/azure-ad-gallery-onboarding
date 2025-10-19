. .\Okta_Creds.ps1

$OktaDomain = ($IssuerURI -replace "/oauth2/default", "")
$Headers = @{
    "Authorization" = "SSWS $TokenValue"
    "Accept" = "application/json"
}

# Get existing apps
$Apps = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps" -Headers $Headers -Method Get

# Find Dropbox app
$DropboxApp = $Apps | Where-Object { $_.label -like "*Dropbox*" }

if ($DropboxApp) {
    Write-Host "Found app: $($DropboxApp.label) (ID: $($DropboxApp.id))" -ForegroundColor Yellow
    Write-Host "Deleting app..." -ForegroundColor Red
    
    # Delete the app
    Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($DropboxApp.id)" -Headers $Headers -Method Delete
    Write-Host "App deleted successfully!" -ForegroundColor Green
} else {
    Write-Host "No Dropbox app found to delete" -ForegroundColor Gray
}