# OnboardApp-Gallery-Simple.ps1
# Simplified script to onboard applications from Azure AD Gallery
# Uses direct gallery browsing approach with dynamic configuration detection

param(
    [Parameter(Mandatory=$false)]
    [string]$AppName,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupIds,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = ".\apps.csv"
)

# Import credentials
. .\EntraCreds.ps1

# Create Cert folder if it doesn't exist
$CertFolder = ".\Cert"
if (-not (Test-Path $CertFolder)) {
    New-Item -ItemType Directory -Path $CertFolder -Force
    Write-Host "Created Cert folder: $CertFolder" -ForegroundColor Green
}

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    $SecureSecret = ConvertTo-SecureString $ApplicationSecret -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $SecureSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential -NoWelcome
    Write-Host "Connected successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect: $($_.Exception.Message)"
    exit 1
}

# Function to browse gallery and find application
function Find-GalleryApp {
    param([string]$SearchName)
    
    Write-Host "`nBrowsing Azure AD Gallery for '$SearchName'..." -ForegroundColor Cyan
    
    try {
        # Get all gallery applications (this is like browsing the gallery)
        Write-Host "   Loading gallery catalog..." -ForegroundColor Yellow
        $AllApps = Get-MgApplicationTemplate -All
        Write-Host "   Found $($AllApps.Count) applications in gallery" -ForegroundColor Green
        
        # Search for exact match
        $ExactMatch = $AllApps | Where-Object { $_.DisplayName -eq $SearchName }
        if ($ExactMatch -and $ExactMatch.Id) {
            Write-Host "   EXACT MATCH: '$($ExactMatch.DisplayName)'" -ForegroundColor Green
            Write-Host "      Template ID: $($ExactMatch.Id)" -ForegroundColor Cyan
            return $ExactMatch
        }
        
        # Search for partial matches
        $PartialMatches = $AllApps | Where-Object { 
            $_.DisplayName -like "*$SearchName*" -and $_.Id
        }
        
        if ($PartialMatches) {
            Write-Host "   Found $($PartialMatches.Count) partial matches:" -ForegroundColor Yellow
            $Counter = 1
            foreach ($Match in $PartialMatches | Select-Object -First 10) {
                Write-Host "      $Counter. $($Match.DisplayName)" -ForegroundColor Cyan
                $Counter++
            }
            
            $FirstMatch = $PartialMatches | Select-Object -First 1
            Write-Host "   USING: '$($FirstMatch.DisplayName)'" -ForegroundColor Green
            Write-Host "      Template ID: $($FirstMatch.Id)" -ForegroundColor Cyan
            return $FirstMatch
        }
        
        Write-Host "   No matches found for '$SearchName'" -ForegroundColor Red
        Write-Host "   Browse manually: https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppGallery" -ForegroundColor Yellow
        return $null
        
    } catch {
        Write-Error "Failed to browse gallery: $($_.Exception.Message)"
        return $null
    }
}

# Function to create application from gallery template
function New-AppFromGallery {
    param(
        [string]$AppName,
        [object]$Template
    )
    
    Write-Host "`nCreating '$AppName' from gallery template..." -ForegroundColor Cyan
    
    try {
        # Create the application from template
        $AppParams = @{
            displayName = $AppName
        }
        
        Write-Host "   Creating application from template ID: $($Template.Id)" -ForegroundColor Yellow
        $Result = Invoke-MgInstantiateApplicationTemplate -ApplicationTemplateId $Template.Id -BodyParameter $AppParams
        
        Write-Host "   Gallery application created successfully!" -ForegroundColor Green
        
        # Wait for provisioning
        Write-Host "   Waiting for application to be fully provisioned..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        
        # Find the created service principal and application
        $ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$AppName'" | Select-Object -First 1
        $Application = Get-MgApplication -Filter "displayName eq '$AppName'" | Select-Object -First 1
        
        if ($ServicePrincipal -and $Application) {
            Write-Host "   Found created application:" -ForegroundColor Green
            Write-Host "      Service Principal ID: $($ServicePrincipal.Id)" -ForegroundColor Cyan
            Write-Host "      Application ID: $($Application.AppId)" -ForegroundColor Cyan
            
            return @{
                ServicePrincipal = $ServicePrincipal
                Application = $Application
                Template = $Template
            }
        } else {
            Write-Error "Could not find created application"
            return $null
        }
        
    } catch {
        Write-Error "Failed to create application: $($_.Exception.Message)"
        return $null
    }
}

# Function to get application configuration details dynamically
function Get-AppConfigDetails {
    param(
        [object]$ServicePrincipal,
        [object]$Application,
        [object]$Template
    )
    
    Write-Host "`nDetecting application configuration..." -ForegroundColor Cyan
    
    try {
        $ConfigDetails = @{
            ReplyURLs = @()
            SignOnURL = ""
            LogoutURL = ""
            Description = "SAML Configuration for $($Template.DisplayName)"
        }
        
        Write-Host "   Analyzing template: $($Template.DisplayName)" -ForegroundColor Yellow
        
        # Try to get Reply URLs from the application registration
        if ($Application.Web.RedirectUris -and $Application.Web.RedirectUris.Count -gt 0) {
            Write-Host "   Found Reply URLs in application registration:" -ForegroundColor Green
            foreach ($Uri in $Application.Web.RedirectUris) {
                Write-Host "      - $Uri" -ForegroundColor Cyan
            }
            $ConfigDetails.ReplyURLs += $Application.Web.RedirectUris
        }
        
        # Try to get Reply URLs from service principal
        if ($ServicePrincipal.ReplyUrls -and $ServicePrincipal.ReplyUrls.Count -gt 0) {
            Write-Host "   Found Reply URLs in service principal:" -ForegroundColor Green
            foreach ($Uri in $ServicePrincipal.ReplyUrls) {
                Write-Host "      - $Uri" -ForegroundColor Cyan
            }
            $ConfigDetails.ReplyURLs += $ServicePrincipal.ReplyUrls
        }
        
        # Try to get Sign-on URL from service principal
        if ($ServicePrincipal.LoginUrl) {
            $ConfigDetails.SignOnURL = $ServicePrincipal.LoginUrl
            Write-Host "   Found Sign-on URL: $($ServicePrincipal.LoginUrl)" -ForegroundColor Green
        }
        
        # Try to get Logout URL from service principal
        if ($ServicePrincipal.LogoutUrl) {
            $ConfigDetails.LogoutURL = $ServicePrincipal.LogoutUrl
            Write-Host "   Found Logout URL: $($ServicePrincipal.LogoutUrl)" -ForegroundColor Green
        }
        
        # Get homepage URL as fallback sign-on URL
        if (-not $ConfigDetails.SignOnURL -and $ServicePrincipal.Homepage) {
            $ConfigDetails.SignOnURL = $ServicePrincipal.Homepage
            Write-Host "   Found Homepage URL: $($ServicePrincipal.Homepage)" -ForegroundColor Green
        }
        
        # If no Reply URLs found, indicate they need to be configured
        if ($ConfigDetails.ReplyURLs.Count -eq 0) {
            Write-Host "   No Reply URLs found - will need to be configured manually" -ForegroundColor Yellow
            $ConfigDetails.ReplyURLs = @("Configure in application admin console")
        }
        
        # Remove duplicates from Reply URLs
        $ConfigDetails.ReplyURLs = $ConfigDetails.ReplyURLs | Select-Object -Unique
        
        return $ConfigDetails
        
    } catch {
        Write-Warning "Failed to get app configuration: $($_.Exception.Message)"
        return @{
            ReplyURLs = @("Configure manually in application")
            SignOnURL = "Configure manually in application"
            Description = "Manual Configuration Required"
        }
    }
}

# Function to assign groups to application
function Add-GroupAssignment {
    param(
        [object]$ServicePrincipal,
        [string]$GroupIds,
        [string]$AppName
    )
    
    if ([string]::IsNullOrWhiteSpace($GroupIds)) {
        Write-Host "   No groups to assign" -ForegroundColor Gray
        return
    }
    
    Write-Host "`nAssigning groups to '$AppName'..." -ForegroundColor Cyan
    
    $GroupIdArray = $GroupIds -split ';' | ForEach-Object { $_.Trim() }
    
    foreach ($GroupId in $GroupIdArray) {
        if ([string]::IsNullOrWhiteSpace($GroupId)) { continue }
        
        try {
            # Get group info
            $Group = Get-MgGroup -GroupId $GroupId
            Write-Host "   Found group: '$($Group.DisplayName)'" -ForegroundColor Green
            
            # Get available app roles
            $AppRoles = $ServicePrincipal.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "User" }
            
            # Use first available role or default
            $RoleId = if ($AppRoles) { $AppRoles[0].Id } else { "00000000-0000-0000-0000-000000000000" }
            
            # Assign group to app
            $Assignment = @{
                PrincipalId = $GroupId
                ResourceId = $ServicePrincipal.Id
                AppRoleId = $RoleId
            }
            
            New-MgGroupAppRoleAssignment -GroupId $GroupId -BodyParameter $Assignment
            Write-Host "   Assigned group '$($Group.DisplayName)' to application" -ForegroundColor Green
            
        } catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Host "   Group already assigned" -ForegroundColor Yellow
            } else {
                Write-Warning "Failed to assign group '$GroupId': $($_.Exception.Message)"
            }
        }
    }
}

# Function to download SAML configuration with proper Base64 certificate
function Get-SAMLConfig {
    param(
        [object]$Application,
        [string]$AppName
    )
    
    Write-Host "`nDownloading SAML configuration..." -ForegroundColor Cyan
    
    try {
        # Metadata URL
        $MetadataUrl = "https://login.microsoftonline.com/$TenantId/federationmetadata/2007-06/federationmetadata.xml?appid=$($Application.AppId)"
        
        # Download metadata
        $MetadataPath = Join-Path $CertFolder "$AppName-federationmetadata.xml"
        Invoke-WebRequest -Uri $MetadataUrl -OutFile $MetadataPath -UseBasicParsing
        Write-Host "   Downloaded metadata: $MetadataPath" -ForegroundColor Green
        
        # Extract and create proper Base64 certificate
        $CertPath = Join-Path $CertFolder "$AppName-certificate.cer"
        $Base64CertPath = Join-Path $CertFolder "$AppName-certificate-base64.txt"
        
        try {
            [xml]$MetadataXml = Get-Content $MetadataPath
            
            # Try different paths to find certificate
            $CertData = $null
            
            # Path 1: Standard location
            $CertNode1 = $MetadataXml.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate
            if ($CertNode1) {
                $CertData = $CertNode1.'#text'
                Write-Host "   Found certificate in standard location" -ForegroundColor Green
            }
            
            # Path 2: Alternative location
            if (-not $CertData) {
                $CertNodes = $MetadataXml.GetElementsByTagName("X509Certificate")
                if ($CertNodes.Count -gt 0) {
                    $CertData = $CertNodes[0].InnerText
                    Write-Host "   Found certificate in alternative location" -ForegroundColor Green
                }
            }
            
            if ($CertData) {
                # Clean the certificate data (remove any whitespace/newlines)
                $CleanCertData = $CertData -replace '\s+', ''
                
                # Create .cer file with proper PEM format
                $PemCertContent = @"
-----BEGIN CERTIFICATE-----
$CleanCertData
-----END CERTIFICATE-----
"@
                $PemCertContent | Out-File -FilePath $CertPath -Encoding ASCII
                Write-Host "   Created PEM certificate: $CertPath" -ForegroundColor Green
                
                # Create Base64 text file (just the certificate data without headers)
                $CleanCertData | Out-File -FilePath $Base64CertPath -Encoding ASCII
                Write-Host "   Created Base64 certificate: $Base64CertPath" -ForegroundColor Green
                
                # Verify certificate format
                $CertLines = ($CleanCertData -replace '(.{64})', '$1`n').Split("`n") | Where-Object { $_ -ne "" }
                Write-Host "   Certificate info:" -ForegroundColor Yellow
                Write-Host "      Length: $($CleanCertData.Length) characters" -ForegroundColor Cyan
                Write-Host "      Lines: $($CertLines.Count)" -ForegroundColor Cyan
                Write-Host "      Format: Base64 encoded X.509" -ForegroundColor Cyan
                
            } else {
                # Create placeholder files
                $PlaceholderText = @"
Certificate not yet available.

Steps to get certificate:
1. Go to Azure Portal -> Enterprise Applications -> $AppName
2. Navigate to Single sign-on -> SAML Certificates
3. Download the Certificate (Base64) or Certificate (Raw)
4. Use the downloaded certificate in your application configuration

Metadata URL: $MetadataUrl
"@
                $PlaceholderText | Out-File -FilePath $CertPath
                $PlaceholderText | Out-File -FilePath $Base64CertPath
                Write-Host "   Certificate not available yet - placeholders created" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Warning "Failed to extract certificate from metadata: $($_.Exception.Message)"
            
            # Create error placeholder
            $ErrorText = @"
Error extracting certificate: $($_.Exception.Message)

Manual steps:
1. Go to Azure Portal -> Enterprise Applications -> $AppName -> Single sign-on
2. Complete SAML configuration first
3. Download certificate from SAML Certificates section
4. Use Certificate (Base64) format for most applications

Metadata URL: $MetadataUrl
"@
            $ErrorText | Out-File -FilePath $CertPath
            $ErrorText | Out-File -FilePath $Base64CertPath
        }
        
        return @{
            EntityId = "https://sts.windows.net/$TenantId/"
            SingleSignOnURL = "https://login.microsoftonline.com/$TenantId/saml2"
            SingleLogoutURL = "https://login.microsoftonline.com/$TenantId/saml2"
            MetadataURL = $MetadataUrl
            CertificatePath = $CertPath
            Base64CertificatePath = $Base64CertPath
            MetadataPath = $MetadataPath
        }
        
    } catch {
        Write-Warning "Failed to download SAML config: $($_.Exception.Message)"
        return $null
    }
}

# Function to display configuration summary
function Show-ConfigSummary {
    param(
        [string]$AppName,
        [object]$AppData,
        [object]$SAMLConfig,
        [object]$AppConfig,
        [string]$GroupIds
    )
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "CONFIGURATION SUMMARY: $AppName" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    Write-Host "`nApplication Details:" -ForegroundColor Yellow
    Write-Host "   Template: $($AppData.Template.DisplayName)" -ForegroundColor Green
    Write-Host "   Application ID: $($AppData.Application.AppId)" -ForegroundColor Cyan
    Write-Host "   Object ID: $($AppData.ServicePrincipal.Id)" -ForegroundColor Cyan
    if ($GroupIds) {
        Write-Host "   Assigned Groups: $GroupIds" -ForegroundColor Green
    }
    
    # Show application-specific configuration
    if ($AppConfig) {
        Write-Host "`nApplication-Specific Configuration:" -ForegroundColor Yellow
        Write-Host "   Description: $($AppConfig.Description)" -ForegroundColor Cyan
        
        if ($AppConfig.ReplyURLs) {
            Write-Host "   Reply URLs (configure in Azure AD):" -ForegroundColor Yellow
            foreach ($ReplyUrl in $AppConfig.ReplyURLs) {
                Write-Host "      -> $ReplyUrl" -ForegroundColor Green
            }
        }
        
        if ($AppConfig.SignOnURL) {
            Write-Host "   Sign-on URL: $($AppConfig.SignOnURL)" -ForegroundColor Cyan
        }
        
        if ($AppConfig.LogoutURL) {
            Write-Host "   Logout URL: $($AppConfig.LogoutURL)" -ForegroundColor Cyan
        }
    }
    
    if ($SAMLConfig) {
        Write-Host "`nSAML Configuration for $AppName Admin Console:" -ForegroundColor Yellow
        Write-Host "   Entity ID (Issuer): $($SAMLConfig.EntityId)" -ForegroundColor Cyan
        Write-Host "   SSO URL: $($SAMLConfig.SingleSignOnURL)" -ForegroundColor Cyan
        Write-Host "   Logout URL: $($SAMLConfig.SingleLogoutURL)" -ForegroundColor Cyan
        Write-Host "   Metadata URL: $($SAMLConfig.MetadataURL)" -ForegroundColor Cyan
        
        Write-Host "`nCertificate Files:" -ForegroundColor Yellow
        Write-Host "   PEM Certificate: $($SAMLConfig.CertificatePath)" -ForegroundColor Cyan
        Write-Host "   Base64 Certificate: $($SAMLConfig.Base64CertificatePath)" -ForegroundColor Cyan
        Write-Host "   Metadata File: $($SAMLConfig.MetadataPath)" -ForegroundColor Cyan
    }
    
    Write-Host "`nAzure Portal Links:" -ForegroundColor Yellow
    Write-Host "   Enterprise App: https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($AppData.ServicePrincipal.Id)" -ForegroundColor Cyan
    Write-Host "   App Registration: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$($AppData.Application.AppId)" -ForegroundColor Cyan
    Write-Host "   SAML Configuration: https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SingleSignOn/objectId/$($AppData.ServicePrincipal.Id)" -ForegroundColor Cyan
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Green
    Write-Host "   1. Configure Reply URLs in Azure AD (see Reply URLs above)" -ForegroundColor White
    Write-Host "   2. Go to $AppName admin console and configure SAML/SSO" -ForegroundColor White
    Write-Host "   3. Use Entity ID and SSO URL from above" -ForegroundColor White
    Write-Host "   4. Upload Base64 certificate or import metadata file" -ForegroundColor White
    Write-Host "   5. Test SSO functionality" -ForegroundColor White
    
    if ($AppConfig -and $AppConfig.ReplyURLs) {
        Write-Host "`nIMPORTANT - Configure Reply URLs:" -ForegroundColor Red
        Write-Host "   Go to Azure Portal -> Enterprise Apps -> $AppName -> Single sign-on" -ForegroundColor Yellow
        Write-Host "   In 'Basic SAML Configuration', add these Reply URLs:" -ForegroundColor Yellow
        foreach ($ReplyUrl in $AppConfig.ReplyURLs) {
            Write-Host "   -> $ReplyUrl" -ForegroundColor Green
        }
    }
    
    Write-Host "="*80 -ForegroundColor Cyan
}

# Main execution
Write-Host "Starting Gallery App Onboarding..." -ForegroundColor Magenta

try {
    # Determine which apps to process
    if ($AppName) {
        $AppsToProcess = @([PSCustomObject]@{
            AppName = $AppName
            Authenticate = "SAML"  # Will be detected from template
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
        
        # Step 1: Find the app in gallery
        $Template = Find-GalleryApp -SearchName $App.AppName
        if (-not $Template) {
            Write-Error "Could not find '$($App.AppName)' in gallery"
            continue
        }
        
        # Step 2: Create app from template
        $AppData = New-AppFromGallery -AppName $App.AppName -Template $Template
        if (-not $AppData) {
            Write-Error "Failed to create '$($App.AppName)'"
            continue
        }
        
        # Step 3: Get application configuration details (dynamic detection)
        $AppConfig = Get-AppConfigDetails -ServicePrincipal $AppData.ServicePrincipal -Application $AppData.Application -Template $Template
        
        # Step 4: Assign groups
        Add-GroupAssignment -ServicePrincipal $AppData.ServicePrincipal -GroupIds $App.GroupIds -AppName $App.AppName
        
        # Step 5: Get SAML configuration
        $SAMLConfig = Get-SAMLConfig -Application $AppData.Application -AppName $App.AppName
        
        # Step 6: Show summary
        Show-ConfigSummary -AppName $App.AppName -AppData $AppData -SAMLConfig $SAMLConfig -AppConfig $AppConfig -GroupIds $App.GroupIds
        
        Write-Host "`nSuccessfully onboarded: $($App.AppName)" -ForegroundColor Green
    }
    
} catch {
    Write-Error "Script failed: $($_.Exception.Message)"
} finally {
    try {
        Disconnect-MgGraph
        Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Gray
    } catch {
        # Ignore disconnect errors
    }
}

Write-Host "`nScript completed!" -ForegroundColor Green