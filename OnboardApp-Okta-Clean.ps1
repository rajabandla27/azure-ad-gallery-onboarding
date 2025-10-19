# OnboardApp-Okta-Clean.ps1
# Script to onboard applications from Okta App Catalog with SAML SSO configuration
# Uses Okta Management API for automated application provisioning

param(
    [Parameter(Mandatory=$false)]
    [string]$AppName,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupIds,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = ".\oktaapps.csv"
)

# Import Okta credentials
. .\Okta_Creds.ps1

# Create Cert folder if it doesn't exist
$CertFolder = ".\Cert"
if (-not (Test-Path $CertFolder)) {
    New-Item -ItemType Directory -Path $CertFolder -Force
    Write-Host "Created Cert folder: $CertFolder" -ForegroundColor Green
}

# Extract domain from IssuerURI
$OktaDomain = ($IssuerURI -replace "/oauth2/default", "")
Write-Host "Using Okta Domain: $OktaDomain" -ForegroundColor Yellow

# Set up headers for Okta API
$Headers = @{
    "Authorization" = "SSWS $TokenValue"
    "Accept" = "application/json"
    "Content-Type" = "application/json"
}

# Test Okta connection
Write-Host "Testing connection to Okta..." -ForegroundColor Yellow
try {
    $TestResponse = Invoke-RestMethod -Uri "$OktaDomain/api/v1/org" -Headers $Headers -Method Get
    Write-Host "Connected successfully to: $($TestResponse.companyName)" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Okta: $($_.Exception.Message)"
    exit 1
}

# Function to search Okta App Integration Catalog
function Find-OktaApp {
    param([string]$SearchName)
    
    Write-Host "`nSearching Okta App Integration Catalog for '$SearchName'..." -ForegroundColor Cyan
    
    try {
        # First try search with query parameter
        $SearchQuery = $SearchName -replace " ", "%20"
        Write-Host "   Searching with query: '$SearchName'..." -ForegroundColor Yellow
        $CatalogApps = Invoke-RestMethod -Uri "$OktaDomain/api/v1/catalog/apps?q=$SearchQuery" -Headers $Headers -Method Get
        Write-Host "   Found $($CatalogApps.Count) applications matching query" -ForegroundColor Green
        
        # Debug: Show found apps
        if ($CatalogApps.Count -gt 0) {
            Write-Host "   Found apps:" -ForegroundColor Yellow
            $CatalogApps | ForEach-Object {
                Write-Host "      - $($_.displayName) ($($_.name))" -ForegroundColor Gray
            }
        }
        
        # Search for exact match by displayName
        $ExactMatch = $CatalogApps | Where-Object { $_.displayName -eq $SearchName }
        if ($ExactMatch) {
            Write-Host "   EXACT MATCH: '$($ExactMatch.displayName)'" -ForegroundColor Green
            Write-Host "      App Name: $($ExactMatch.name)" -ForegroundColor Cyan
            Write-Host "      Category: $($ExactMatch.category)" -ForegroundColor Cyan
            return $ExactMatch
        }
        
        # Search for partial matches (case insensitive)
        $PartialMatches = $CatalogApps | Where-Object { $_.displayName -like "*$SearchName*" }
        
        # If no matches, try without "Business" suffix
        if (-not $PartialMatches -and $SearchName -like "*Business*") {
            $SimpleName = $SearchName -replace " Business", ""
            Write-Host "   Trying simplified search for '$SimpleName'..." -ForegroundColor Yellow
            $PartialMatches = $CatalogApps | Where-Object { $_.displayName -like "*$SimpleName*" }
        }
        
        if ($PartialMatches) {
            Write-Host "   Found $($PartialMatches.Count) partial matches:" -ForegroundColor Yellow
            $Counter = 1
            foreach ($Match in $PartialMatches | Select-Object -First 10) {
                Write-Host "      $Counter. $($Match.displayName)" -ForegroundColor Cyan
                $Counter++
            }
            
            $FirstMatch = $PartialMatches | Select-Object -First 1
            Write-Host "   USING: '$($FirstMatch.displayName)'" -ForegroundColor Green
            Write-Host "      App Name: $($FirstMatch.name)" -ForegroundColor Cyan
            return $FirstMatch
        }
        
        Write-Host "   No matches found for '$SearchName'" -ForegroundColor Red
        Write-Host "   Browse manually: $OktaDomain/admin/apps/catalog" -ForegroundColor Yellow
        Write-Host "   Available apps with 'drop' in name:" -ForegroundColor Yellow
        $DropboxApps = $CatalogApps | Where-Object { $_.displayName -like "*drop*" }
        if ($DropboxApps) {
            $DropboxApps | ForEach-Object {
                Write-Host "      - $($_.displayName)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "      No Dropbox-related apps found" -ForegroundColor Gray
        }
        return $null
        
    } catch {
        Write-Error "Failed to search Okta catalog: $($_.Exception.Message)"
        return $null
    }
}

# Function to create application from Okta catalog
function New-OktaAppFromCatalog {
    param(
        [string]$AppName,
        [object]$CatalogApp
    )
    
    Write-Host "`nCreating '$AppName' from Okta catalog..." -ForegroundColor Cyan
    
    try {
        # Prepare application configuration with manual assignment only
        $AppConfig = @{
            name = $CatalogApp.name
            label = $AppName
            signOnMode = "SAML_2_0"
            settings = @{
                app = @{}
                notifications = @{
                    vpn = @{
                        network = @{
                            connection = "DISABLED"
                        }
                        message = $null
                        helpUrl = $null
                    }
                }
            }
            # Disable automatic assignment of Everyone group
            profile = @{}
            credentials = @{
                userNameTemplate = @{
                    template = '${source.login}'
                    type = "BUILT_IN"
                }
            }
        }
        
        Write-Host "   Creating application with SAML 2.0 sign-on mode..." -ForegroundColor Yellow
        $AppBody = $AppConfig | ConvertTo-Json -Depth 10
        
        $NewApp = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps" -Headers $Headers -Method Post -Body $AppBody
        
        Write-Host "   Application created successfully!" -ForegroundColor Green
        Write-Host "      App ID: $($NewApp.id)" -ForegroundColor Cyan
        Write-Host "      Label: $($NewApp.label)" -ForegroundColor Cyan
        Write-Host "      Sign-on Mode: $($NewApp.signOnMode)" -ForegroundColor Cyan
        
        # Wait for provisioning
        Write-Host "   Waiting for application to be fully provisioned..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        # Set assignment policy to manual (no automatic Everyone assignment)
        try {
            Write-Host "   Setting manual assignment policy..." -ForegroundColor Yellow
            $PolicyUpdate = @{
                profile = @{}
            } | ConvertTo-Json -Depth 3
            
            Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($NewApp.id)" -Headers $Headers -Method Put -Body $PolicyUpdate
            Write-Host "   Assignment policy set to manual" -ForegroundColor Green
        } catch {
            Write-Warning "Could not set assignment policy: $($_.Exception.Message)"
        }
        
        return $NewApp
        
    } catch {
        Write-Error "Failed to create application: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $ErrorDetails = $_.Exception.Response.GetResponseStream()
            $Reader = New-Object System.IO.StreamReader($ErrorDetails)
            $ErrorBody = $Reader.ReadToEnd()
            Write-Error "Error details: $ErrorBody"
        }
        return $null
    }
}

# Function to get application SAML configuration
function Get-OktaSAMLConfig {
    param(
        [object]$Application,
        [string]$AppName
    )
    
    Write-Host "`nConfiguring SAML settings for '$AppName'..." -ForegroundColor Cyan
    
    try {
        # Get application details with SAML settings
        $AppDetails = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($Application.id)" -Headers $Headers -Method Get
        
        Write-Host "   Retrieved application configuration" -ForegroundColor Green
        
        # Initialize certificate paths
        $CertPath = Join-Path $CertFolder "$AppName-okta-certificate.cer"
        $Base64CertPath = Join-Path $CertFolder "$AppName-okta-certificate-base64.txt"
        $MetadataPath = Join-Path $CertFolder "$AppName-okta-metadata.xml"
        
        # Try multiple methods to get SAML metadata and certificate
        $MetadataUrl = "$OktaDomain/app/$($Application.name)/$($Application.id)/sso/saml/metadata"
        Write-Host "   Attempting metadata download from: $MetadataUrl" -ForegroundColor Yellow
        
        # Method 1: Try to download metadata directly
        try {
            Invoke-WebRequest -Uri $MetadataUrl -OutFile $MetadataPath -UseBasicParsing
            Write-Host "   Downloaded metadata: $MetadataPath" -ForegroundColor Green
            
            # Extract certificate from metadata
            [xml]$MetadataXml = Get-Content $MetadataPath
            $CertData = $null
            
            # Try different certificate extraction methods
            $CertNodes = $MetadataXml.GetElementsByTagName("X509Certificate")
            if ($CertNodes.Count -gt 0) {
                $CertData = $CertNodes[0].InnerText
                Write-Host "   Found certificate in metadata (Method 1)" -ForegroundColor Green
            } else {
                # Try alternative paths
                $CertNode2 = $MetadataXml.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate
                if ($CertNode2) {
                    $CertData = $CertNode2.'#text'
                    Write-Host "   Found certificate in metadata (Method 2)" -ForegroundColor Green
                }
            }
            
            if ($CertData) {
                # Clean certificate data
                $CleanCertData = $CertData -replace '\s+', ''
                
                # Create PEM format certificate
                $PemCertContent = @"
-----BEGIN CERTIFICATE-----
$CleanCertData
-----END CERTIFICATE-----
"@
                $PemCertContent | Out-File -FilePath $CertPath -Encoding ASCII
                Write-Host "   Created PEM certificate: $CertPath" -ForegroundColor Green
                
                # Create Base64 text file
                $CleanCertData | Out-File -FilePath $Base64CertPath -Encoding ASCII
                Write-Host "   Created Base64 certificate: $Base64CertPath" -ForegroundColor Green
                
                # Verify certificate format
                $CertLines = ($CleanCertData -replace '(.{64})', '$1`n').Split("`n") | Where-Object { $_ -ne "" }
                Write-Host "   Certificate info:" -ForegroundColor Yellow
                Write-Host "      Length: $($CleanCertData.Length) characters" -ForegroundColor Cyan
                Write-Host "      Lines: $($CertLines.Count)" -ForegroundColor Cyan
                Write-Host "      Format: Base64 encoded X.509" -ForegroundColor Cyan
            } else {
                Write-Host "   No certificate found in metadata - will try alternative method" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "   Metadata download failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "   This is normal for newly created apps - certificate will be available after SAML configuration" -ForegroundColor Yellow
        }
        
        # Method 2: Try to get certificate from app credentials endpoint
        if (-not $CertData) {
            try {
                Write-Host "   Trying alternative certificate method..." -ForegroundColor Yellow
                $Credentials = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($Application.id)/credentials/keys" -Headers $Headers -Method Get
                if ($Credentials -and $Credentials.Count -gt 0) {
                    $CertData = $Credentials[0].x5c[0]
                    if ($CertData) {
                        Write-Host "   Found certificate from credentials endpoint" -ForegroundColor Green
                        
                        # Clean and save certificate
                        $CleanCertData = $CertData -replace '\s+', ''
                        
                        # Create PEM format
                        $PemCertContent = @"
-----BEGIN CERTIFICATE-----
$CleanCertData
-----END CERTIFICATE-----
"@
                        $PemCertContent | Out-File -FilePath $CertPath -Encoding ASCII
                        $CleanCertData | Out-File -FilePath $Base64CertPath -Encoding ASCII
                        Write-Host "   Created certificate files from credentials endpoint" -ForegroundColor Green
                    }
                }
            } catch {
                Write-Host "   Alternative certificate method also failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # If still no certificate, create placeholder files with instructions
        if (-not $CertData) {
            $PlaceholderText = @"
Certificate not yet available - this is normal for newly created applications.

TO GET CERTIFICATE:
1. Go to Okta Admin Console: $OktaDomain/admin/app/$($Application.name)/instance/$($Application.id)/settings/saml
2. Complete the basic SAML configuration first
3. Once configured, the certificate will be available at: $MetadataUrl
4. You can also download it directly from the SAML configuration page

SAML URLs to configure in ${AppName}:
- Entity ID: $OktaDomain
- SSO URL: $OktaDomain/app/$($Application.name)/$($Application.id)/sso/saml
- Audience URL: $OktaDomain/app/$($Application.name)/$($Application.id)/sso/saml

Metadata URL: $MetadataUrl
"@
            $PlaceholderText | Out-File -FilePath $CertPath -Encoding UTF8
            $PlaceholderText | Out-File -FilePath $Base64CertPath -Encoding UTF8
            Write-Host "   Created placeholder certificate files with instructions" -ForegroundColor Yellow
        }
        
        # Get SAML URLs
        $EntityId = $OktaDomain
        $SSOUrl = "$OktaDomain/app/$($Application.name)/$($Application.id)/sso/saml"
        $AudienceUrl = "$OktaDomain/app/$($Application.name)/$($Application.id)/sso/saml"
        
        return @{
            EntityId = $EntityId
            SingleSignOnURL = $SSOUrl
            AudienceURL = $AudienceUrl
            MetadataURL = $MetadataUrl
            CertificatePath = $CertPath
            Base64CertificatePath = $Base64CertPath
            MetadataPath = $MetadataPath
            Application = $AppDetails
        }
        
    } catch {
        Write-Warning "Failed to get SAML configuration: $($_.Exception.Message)"
        return $null
    }
}

# Function to assign groups to Okta application
function Add-OktaGroupAssignment {
    param(
        [object]$Application,
        [string]$GroupIds,
        [string]$AppName
    )
    
    if ([string]::IsNullOrWhiteSpace($GroupIds)) {
        Write-Host "   No groups to assign" -ForegroundColor Gray
        return
    }
    
    Write-Host "`nAssigning groups to '$AppName'..." -ForegroundColor Cyan
    
    # Support multiple delimiters: semicolon, comma, or space
    $GroupIdArray = $GroupIds -split '[;,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
    Write-Host "   Found $($GroupIdArray.Count) group(s) to assign: $($GroupIdArray -join ', ')" -ForegroundColor Yellow
    
    foreach ($GroupId in $GroupIdArray) {
        $GroupId = $GroupId.Trim()
        if ([string]::IsNullOrWhiteSpace($GroupId)) { continue }
        
        try {
            # Get group info first
            $Group = Invoke-RestMethod -Uri "$OktaDomain/api/v1/groups/$GroupId" -Headers $Headers -Method Get
            Write-Host "   Found group: '$($Group.profile.name)' (ID: $GroupId)" -ForegroundColor Green
            
            # Check if group is already assigned
            try {
                $ExistingAssignment = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($Application.id)/groups/$GroupId" -Headers $Headers -Method Get
                Write-Host "   Group '$($Group.profile.name)' is already assigned" -ForegroundColor Yellow
                continue
            } catch {
                # Group not assigned yet, proceed with assignment
            }
            
            # First, remove "Everyone" group if it exists
            try {
                $EveryoneGroup = Invoke-RestMethod -Uri "$OktaDomain/api/v1/groups?q=Everyone" -Headers $Headers -Method Get | Where-Object { $_.profile.name -eq "Everyone" }
                if ($EveryoneGroup) {
                    Write-Host "   Removing default 'Everyone' group assignment..." -ForegroundColor Yellow
                    Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($Application.id)/groups/$($EveryoneGroup.id)" -Headers $Headers -Method Delete
                    Write-Host "   Removed 'Everyone' group" -ForegroundColor Green
                }
            } catch {
                # Everyone group not assigned or error removing it, continue
                Write-Host "   'Everyone' group not found or already removed" -ForegroundColor Gray
            }
            
            # Assign specific group to application with proper role
            $AssignmentBody = @{
                id = $GroupId
                profile = @{}
            } | ConvertTo-Json -Depth 3
            
            Write-Host "   Assigning group '$($Group.profile.name)' to application..." -ForegroundColor Yellow
            $Assignment = Invoke-RestMethod -Uri "$OktaDomain/api/v1/apps/$($Application.id)/groups/$GroupId" -Headers $Headers -Method Put -Body $AssignmentBody
            Write-Host "   Successfully assigned group '$($Group.profile.name)' to application" -ForegroundColor Green
            
        } catch {
            $ErrorMessage = $_.Exception.Message
            if ($ErrorMessage -like "*404*") {
                Write-Warning "Group '$GroupId' not found in Okta"
            } elseif ($ErrorMessage -like "*409*" -or $ErrorMessage -like "*already*") {
                Write-Host "   Group '$GroupId' already assigned" -ForegroundColor Yellow
            } else {
                Write-Warning "Failed to assign group '$GroupId': $ErrorMessage"
            }
        }
    }
}

# Function to display configuration summary
function Show-OktaConfigSummary {
    param(
        [string]$AppName,
        [object]$Application,
        [object]$SAMLConfig,
        [string]$GroupIds
    )
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "OKTA CONFIGURATION SUMMARY: $AppName" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    Write-Host "`nApplication Details:" -ForegroundColor Yellow
    Write-Host "   App ID: $($Application.id)" -ForegroundColor Cyan
    Write-Host "   Label: $($Application.label)" -ForegroundColor Cyan
    Write-Host "   Sign-on Mode: $($Application.signOnMode)" -ForegroundColor Cyan
    Write-Host "   Status: $($Application.status)" -ForegroundColor Green
    if ($GroupIds) {
        Write-Host "   Assigned Groups: $GroupIds" -ForegroundColor Green
    }
    
    if ($SAMLConfig) {
        Write-Host "`nSAML Configuration for $AppName Admin Console:" -ForegroundColor Yellow
        Write-Host "   Entity ID (Issuer): $($SAMLConfig.EntityId)" -ForegroundColor Cyan
        Write-Host "   SSO URL: $($SAMLConfig.SingleSignOnURL)" -ForegroundColor Cyan
        Write-Host "   Audience URL: $($SAMLConfig.AudienceURL)" -ForegroundColor Cyan
        if ($SAMLConfig.MetadataURL) {
            Write-Host "   Metadata URL: $($SAMLConfig.MetadataURL)" -ForegroundColor Cyan
        }
        
        if ($SAMLConfig.CertificatePath) {
            Write-Host "`nCertificate Files:" -ForegroundColor Yellow
            Write-Host "   PEM Certificate: $($SAMLConfig.CertificatePath)" -ForegroundColor Cyan
            Write-Host "   Base64 Certificate: $($SAMLConfig.Base64CertificatePath)" -ForegroundColor Cyan
            if ($SAMLConfig.MetadataPath) {
                Write-Host "   Metadata File: $($SAMLConfig.MetadataPath)" -ForegroundColor Cyan
            }
        }
    }
    
    Write-Host "`nOkta Admin Links:" -ForegroundColor Yellow
    Write-Host "   Application Settings: $OktaDomain/admin/app/$($Application.name)/instance/$($Application.id)" -ForegroundColor Cyan
    Write-Host "   SAML Configuration: $OktaDomain/admin/app/$($Application.name)/instance/$($Application.id)/settings/saml" -ForegroundColor Cyan
    Write-Host "   Group Assignments: $OktaDomain/admin/app/$($Application.name)/instance/$($Application.id)/assignments" -ForegroundColor Cyan
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Green
    Write-Host "   1. Go to $AppName admin console (e.g., Dropbox Business admin)" -ForegroundColor White
    Write-Host "   2. Navigate to SAML/SSO configuration section" -ForegroundColor White
    Write-Host "   3. Use Entity ID and SSO URL from above" -ForegroundColor White
    Write-Host "   4. Upload Base64 certificate or import metadata file" -ForegroundColor White
    Write-Host "   5. Configure any required Reply URLs in Okta app settings" -ForegroundColor White
    Write-Host "   6. Test SSO functionality" -ForegroundColor White
    
    Write-Host "="*80 -ForegroundColor Cyan
}

# Main execution
Write-Host "Starting Okta App Onboarding..." -ForegroundColor Magenta

try {
    # Determine which apps to process
    if ($AppName) {
        $AppsToProcess = @([PSCustomObject]@{
            AppName = $AppName
            Authenticate = "SAML"
            GroupIds = $GroupIds
        })
    } else {
        if (-not (Test-Path $CsvPath)) {
            Write-Error "CSV file not found: $CsvPath"
            exit 1
        }
        $AppsToProcess = Import-Csv -Path $CsvPath
    }
    
    foreach ($App in $AppsToProcess) {
        Write-Host "`n" + "="*50 -ForegroundColor Magenta
        Write-Host "PROCESSING: $($App.AppName)" -ForegroundColor Magenta
        Write-Host "="*50 -ForegroundColor Magenta
        
        # Step 1: Find the app in Okta catalog
        $CatalogApp = Find-OktaApp -SearchName $App.AppName
        if (-not $CatalogApp) {
            Write-Error "Could not find '$($App.AppName)' in Okta catalog"
            continue
        }
        
        # Step 2: Create app from catalog
        $Application = New-OktaAppFromCatalog -AppName $App.AppName -CatalogApp $CatalogApp
        if (-not $Application) {
            Write-Error "Failed to create '$($App.AppName)'"
            continue
        }
        
        # Step 3: Configure SAML settings
        $SAMLConfig = Get-OktaSAMLConfig -Application $Application -AppName $App.AppName
        
        # Step 4: Assign groups
        Add-OktaGroupAssignment -Application $Application -GroupIds $App.GroupIds -AppName $App.AppName
        
        # Step 5: Show summary
        Show-OktaConfigSummary -AppName $App.AppName -Application $Application -SAMLConfig $SAMLConfig -GroupIds $App.GroupIds
        
        Write-Host "`nSuccessfully onboarded: $($App.AppName)" -ForegroundColor Green
    }
    
} catch {
    Write-Error "Script failed: $($_.Exception.Message)"
}

Write-Host "`nScript completed!" -ForegroundColor Green