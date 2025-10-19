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
    Write-Host "Status: $($DropboxApp.status)" -ForegroundColor Gray
    
    try {
        # Step 1: Deactivate the app first if it's active
        if ($DropboxApp.status -eq "ACTIVE") {
            Write-Host "Deactivating app..." -ForegroundColor Yellow
            Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($DropboxApp.id)/lifecycle/deactivate" -Headers $Headers -Method Post
            Write-Host "App deactivated successfully!" -ForegroundColor Green
            
            # Wait a moment for deactivation to complete
            Start-Sleep -Seconds 2
        }
        
        # Step 2: Delete the deactivated app
        Write-Host "Deleting app..." -ForegroundColor Red
        Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($DropboxApp.id)" -Headers $Headers -Method Delete
        Write-Host "App deleted successfully!" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to delete app: $($_.Exception.Message)"
        
        # Try to parse the error response
        if ($_.Exception.Response) {
            try {
                $ErrorDetails = $_.Exception.Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($ErrorDetails)
                $ErrorBody = $Reader.ReadToEnd()
                Write-Host "Error details: $ErrorBody" -ForegroundColor Red
            } catch {
                # Ignore error parsing errors
            }
        }
    }
} else {
    Write-Host "No Dropbox app found to delete" -ForegroundColor Gray
}


<#
# Load Okta credentials
. .\Okta_Creds.ps1

$OktaDomain = ($IssuerURI -replace "/oauth2/default", "")
$Headers = @{
    "Authorization" = "SSWS $TokenValue"
    "Accept" = "application/json"
}

$GroupName = "Dropbox Users" # Change to your group name

# Search for group by name
$Groups = Invoke-RestMethod -Uri "$OktaDomain/api/v1/groups?q=$GroupName" -Headers $Headers -Method Get

if ($Groups) {
    foreach ($Group in $Groups) {
        Write-Host "Group: $($Group.profile.name) | ID: $($Group.id)"
    }
} else {
    Write-Host "No group found with name: $GroupName"
}
    #>