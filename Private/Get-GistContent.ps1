function Get-GistContent {
    <#
    .SYNOPSIS
        A short one-line action-based description, e.g. 'Tests if a function is valid'
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Get-GistContent https://gist.github.com/alainQtec/34c60b903f3c1c9d51ec5f0ee3a82adb
        Will get contents of the first file found in the gist
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        # File name with extention
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$FileName,
        # url string, can be a raw_url or just a normal gist url
        [Parameter(Mandatory = $false)]
        [string]$GistUrl
    )

    begin {
        enum EncryptionScope {
            User    # The encrypted data can be decrypted with the same user on any machine.
            Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
        }
        enum Compression {
            Gzip
            Deflate
            ZLib
        }

        class GitHub {
            static $webSession
            static [string] $UserName
            static hidden [bool] $IsInteractive = $false
            static hidden [string] $TokenFile = [GitHub]::GetTokenFile()

            static [PSObject] createSession() {
                return [Github]::createSession([Github]::UserName)
            }
            static [PSObject] createSession([string]$UserName) {
                [GitHub]::SetToken()
                return [GitHub]::createSession($UserName, [GitHub]::GetToken())
            }
            static [Psobject] createSession([string]$GitHubUserName, [securestring]$clientSecret) {
                [ValidateNotNullOrEmpty()][string]$GitHubUserName = $GitHubUserName
                [ValidateNotNullOrEmpty()][string]$GithubToken = $GithubToken = [AesCrypt]::GetString([securestring]$clientSecret)
                $encodedAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($GitHubUserName):$($GithubToken)"))
                $web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
                [void]$web_session.Headers.Add('Authorization', "Basic $($encodedAuth)")
                [void]$web_session.Headers.Add('Accept', 'application/vnd.github.v3+json')
                [GitHub]::webSession = $web_session
                return $web_session
            }
            static [void] SetToken() {
                [GitHub]::SetToken([AesCrypt]::GetString((Read-Host -Prompt "[GitHub] Paste/write your api token" -AsSecureString)), $(Read-Host -Prompt "[GitHub] Paste/write a Password to encrypt the token" -AsSecureString))
            }
            static [void] SetToken([string]$token, [securestring]$password) {
                if (![IO.File]::Exists([GitHub]::TokenFile)) { New-Item -Type File -Path ([GitHub]::TokenFile) -Force | Out-Null }
                [IO.File]::WriteAllText([GitHub]::TokenFile, [convert]::ToBase64String([AesCrypt]::Encrypt([system.Text.Encoding]::UTF8.GetBytes($token), $password)), [System.Text.Encoding]::UTF8);
            }
            static [securestring] GetToken() {
                $sectoken = $null; $session_pass = [AesCrypt]::GetSecureString('123');
                try {
                    if ([GitHub]::IsInteractive) {
                        if ([string]::IsNullOrWhiteSpace((Get-Content ([GitHub]::TokenFile) -ErrorAction Ignore))) {
                            Write-Host "[GitHub] You'll need to set your api token first. This is a One-Time Process :)" -ForegroundColor Green
                            [GitHub]::SetToken()
                            Write-Host "[GitHub] Good, now let's use the api token :)" -ForegroundColor DarkGreen
                        } elseif ([GitHub]::ValidateBase64String([IO.File]::ReadAllText([GitHub]::TokenFile))) {
                            Write-Host "[GitHub] Encrypted token found in file: $([GitHub]::TokenFile)" -ForegroundColor DarkGreen
                        } else {
                            throw [System.Exception]::New("Unable to read token file!")
                        }
                        $session_pass = Read-Host -Prompt "[GitHub] Input password to use your token" -AsSecureString
                    } else {
                        #Fix: Temporary Workaround: Thisz a pat from one of my GitHub a/cs.It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!!
                        $et = "OOLqqov4ugMQAtFcWqbzRwNBD65uf9JOZ+jzx1RtcHAZtnKaq1zkIpBcuv1MQfOkvIr/V066Zgsaq5Gka+VhlbqhV8apm8zcQomYjYqLaECKAonFeeo9MqvaP1F2VLgXokrxD1M6weLwS7KC+dyvAgv10IEvLzWFMw=="
                        [GitHub]::SetToken([convert]::ToBase64String([aescrypt]::Decrypt([convert]::FromBase64String($et), $session_pass)), $session_pass)
                    }
                    $sectoken = [AesCrypt]::GetSecureString([system.Text.Encoding]::UTF8.GetString(
                            [AesCrypt]::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText([GitHub]::GetTokenFile())), $session_pass)
                        )
                    )
                } catch {
                    throw $_
                }
                return $sectoken
            }
            static [PsObject] GetUserInfo([string]$UserName) {
                if ([string]::IsNullOrWhiteSpace([GitHub]::userName)) { [GitHub]::createSession() }
                $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
                return $response
            }
            static [PsObject] GetGist([uri]$Uri) {
                $l = [GitHub]::ParseGistUri($Uri)
                return [GitHub]::GetGist($l.Owner, $l.Id)
            }
            static [PsObject] GetGist([string]$UserName, [string]$GistId) {
                $t = [GitHub]::GetToken()
                if ($null -eq ([GitHub]::webSession)) {
                    [GitHub]::webSession = $(if ($null -eq $t) {
                            [GitHub]::createSession($UserName)
                        } else {
                            [GitHub]::createSession($UserName, $t)
                        }
                    )
                }
                if (![GitHub]::IsConnected()) {
                    throw [System.Net.NetworkInformation.PingException]::new("PingException, PLease check your connection!");
                }
                if ([string]::IsNullOrWhiteSpace($GistId) -or $GistId -eq '*') {
                    return Get-Gists -UserName $UserName -SecureToken $t
                }
                return Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
            }
            Static [string] GetGistContent([string]$FileName, [uri]$GistUri) {
                return [GitHub]::GetGist($GistUri).files.$FileName.content
            }
            static [PsObject] CreateGist([string]$description, [array]$files) {
                $url = 'https://api.github.com/gists'
                $body = @{
                    description = $description
                    files       = @{}
                }
                foreach ($file in $files) {
                    $body.files[$file.Name] = @{
                        content = $file.Content
                    }
                }
                $response = Invoke-RestMethod -Uri $url -WebSession ([GitHub]::webSession) -Method Post -Body ($body | ConvertTo-Json) -Verbose:$false
                return $response
            }
            static [PsObject] UpdateGist([GistFile]$gist, [string]$NewContent) {
                return ''
            }
            static [string] GetTokenFile() {
                if (![IO.File]::Exists([GitHub]::TokenFile)) {
                    [GitHub]::TokenFile = [IO.Path]::Combine([GitHub]::Get_dataPath('Github', 'clicache'), "token");
                }
                return [GitHub]::TokenFile
            }
            static [GistFile] ParseGistUri([uri]$GistUri) {
                $res = $null; $ogs = $GistUri.OriginalString
                $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
                $seg = $GistUri.Segments
                $res = $(if ($IsRawUri) {
                        $name = $seg[-1]
                        $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                        $rtri = $rtri.Remove($rtri.Length - 1)
                        $info = [GitHub]::GetGist([uri]::new($rtri))
                        $file = $info.files."$name"
                        [PsCustomObject]@{
                            language = $file.language
                            IsPublic = $info.IsPublic
                            raw_url  = $file.raw_url
                            Owner    = $info.owner.login
                            type     = $file.type
                            filename = $name
                            size     = $file.size
                            Id       = $seg[2].Replace('/', '')
                        }
                    } else {
                        # $info = [GitHub]::GetGist($GistUri)
                        [PsCustomObject]@{
                            language = ''
                            IsPublic = $null
                            raw_url  = ''
                            Owner    = $seg[1].Split('/')[0]
                            type     = ''
                            filename = ''
                            size     = ''
                            Id       = $seg[-1]
                        }
                    }
                )
                return [GistFile]::New($res)
            }
            static [PsObject] GetUserRepositories() {
                if ($null -eq [GitHub]::webSession) { [Github]::createSession() }
                $response = Invoke-RestMethod -Uri 'https://api.github.com/user/repos' -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
                return $response
            }
            static [psobject] ParseLink([string]$text, [bool]$throwOnFailure) {
                [ValidateNotNullOrEmpty()][string]$text = $text
                $uri = $text -as 'Uri'; if ($uri -isnot [Uri] -and $throwOnFailure) {
                    throw [System.InvalidOperationException]::New("Could not create uri from text '$text'.")
                }; $Scheme = $uri.Scheme
                if ([regex]::IsMatch($text, '^(\/[a-zA-Z0-9_-]+)+|([a-zA-Z]:\\(((?![<>:"\/\\|?*]).)+\\?)*((?![<>:"\/\\|?*]).)+)$')) {
                    if ($text.ToCharArray().Where({ $_ -in [IO.Path]::InvalidPathChars }).Count -eq 0) {
                        $Scheme = 'file'
                    } else {
                        Write-Debug "'$text' has invalidPathChars in it !" -Debug
                    }
                }
                $IsValid = $Scheme -in @('file', 'https')
                $IsGistUrl = [Regex]::IsMatch($text, "^https://gist.github.com/[a-z0-9]+(?:/[a-z0-9]+)?$")
                $OutptObject = [pscustomobject]@{
                    FullName = $text
                    Scheme   = [PSCustomObject]@{
                        Name      = $Scheme
                        IsValid   = $IsValid
                        IsGistUrl = $IsGistUrl
                    }
                }
                return $OutptObject
            }
            static [string] Get_Host_Os() {
                # Todo: Should return one of these: [Enum]::GetNames([System.PlatformID])
                return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
            }
            static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
                $_Host_OS = [GitHub]::Get_Host_Os()
                $dataPath = if ($_Host_OS -eq 'Windows') {
                    [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", $appName, $SubdirName))
                } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
                    [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
                } elseif ($_Host_OS -eq 'Unknown') {
                    try {
                        [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
                    } catch {
                        Write-Warning "Could not resolve chat data path"
                        Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
                        [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
                    }
                } else {
                    throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
                }
                if (!$dataPath.Exists) { [GitHub]::Create_Dir($dataPath) }
                return $dataPath
            }
            static [void] Create_Dir([string]$Path) {
                [GitHub]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
            }
            static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
                [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
                $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
                [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
            }
            static [bool] ValidateBase64String([string]$base64) {
                return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
            }
            static [bool] IsConnected() {
                if (![bool]("System.Net.NetworkInformation.Ping" -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
                $cs = $null; $re = @{ true = @{ m = "Success"; c = "Green" }; false = @{ m = "Failed"; c = "Red" } }
                Write-Host "[Github] Testing Connection ... " -ForegroundColor Blue -NoNewline
                try {
                    [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("github.com");
                    $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
                } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
                    $cs = $false
                } catch {
                    $cs = $false;
                    Write-Error $_
                }
                $re = $re[$cs.ToString()]
                Write-Host $re.m -ForegroundColor $re.c
                return $cs
            }
        }
        class GistFile {
            [string]$Name
            [string]$language
            [string]$raw_url
            [bool]$IsPublic
            [string]$Owner
            [string]$type
            [string]$Id
            [int]$size

            GistFile([string]$filename) {
                $this.Name = $filename
            }
            GistFile([PsObject]$InputObject) {
                $this.language = $InputObject.language
                $this.IsPublic = $InputObject.IsPublic
                $this.raw_url = $InputObject.raw_url
                $this.Owner = $InputObject.Owner
                $this.type = $InputObject.type
                $this.Name = $InputObject.filename
                $this.size = $InputObject.size
                $this.Id = $InputObject.Id
            }
            [string] ShowFileInfo() {
                return "File: $($this.Name)"
            }
        }

        class Gist {
            [uri] $Uri
            [string] $Id
            [string] $Owner
            [string] $Description
            [bool] $IsPublic
            [GistFile[]] $Files = @()

            Gist() {}
            Gist([string]$Name) {
                $this.AddFile([GistFile]::new($Name))
            }
            [psobject] Post() {
                $gisfiles = @()
                $this.Files.Foreach({
                        $gisfiles += @{
                            $_.Name = @{
                                content = $_.Content
                            }
                        }
                    }
                )
                $data = @{
                    files       = $gisfiles
                    description = $this.Description
                    public      = $this.IsPublic
                } | ConvertTo-Json

                Write-Verbose ($data | Out-String)
                Write-Verbose "[PROCESS] Posting to https://api.github.com/gists"
                $invokeParams = @{
                    Method      = 'Post'
                    Uri         = "https://api.github.com/gists"
                    WebSession  = [GitHub]::webSession
                    Body        = $data
                    ContentType = 'application/json'
                }
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $r = Invoke-RestMethod @invokeParams
                $r = $r | Select-Object @{Name = "Url"; Expression = { $_.html_url } }, Description, Public, @{Name = "Created"; Expression = { $_.created_at -as [datetime] } }
                return $r
            }
            [void] AddFile([GistFile]$file) {
                $this.Files += $file
            }
            [string] ShowInfo() {
                $info = "Gist ID: $($this.Id)"
                $info += "`nDescription: $($this.Description)"
                $info += "`nFiles:"
                foreach ($file in $this.Files.Values) {
                    $info += "`n  - $($file.ShowFileInfo())"
                }
                return $info
            }
        }
        class Shuffl3r {
            static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
                return [Shuffl3r]::Combine($bytes, $Nonce, [AesCrypt]::GetString($Passwod))
            }
            static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
                # if ($Bytes.Length -lt 16) { throw [InvalidArgumentException]::New('Bytes', 'Input bytes.length should be > 16. ie: $minLength = 17, since the common $nonce length is 16') }
                if ($bytes.Length -lt ($Nonce.Length + 1)) {
                    Write-Debug "Bytes.Length = $($Bytes.Length) but Nonce.Length = $($Nonce.Length)" -Debug
                    throw [System.ArgumentOutOfRangeException]::new("Nonce", 'Make sure $Bytes.length > $Nonce.Length')
                }
                if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
                [int[]]$Indices = [int[]]::new($Nonce.Length);
                Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
                [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
                for ([int]$i = 0; $i -lt $Indices.Length; $i++) {
                    $combined[$Indices[$i]] = $Nonce[$i]
                }
                $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
                foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
                return $combined
            }
            static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
                return [Shuffl3r]::Split($ShuffledBytes, [AesCrypt]::GetString($Passwod), [int]$NonceLength);
            }
            static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
                if ($null -eq $ShuffledBytes) { throw [System.ArgumentNullException]::new('$ShuffledBytes') }
                if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
                [int[]]$Indices = [int[]]::new([int]$NonceLength);
                Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
                $Nonce = [Byte[]]::new($NonceLength);
                $bytes = [Byte[]]$((0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices } | Select-Object *, @{l = 'bytes'; e = { $ShuffledBytes[$_] } }).bytes
                for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
                return ($bytes, $Nonce)
            }
            static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
                if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [System.ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
                if ([string]::IsNullOrWhiteSpace($randomString)) { throw [System.ArgumentNullException]::new('$randomString') }
                [Byte[]]$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$randomString))
                [int[]]$indices = [int[]]::new($Count)
                for ($i = 0; $i -lt $Count; $i++) {
                    [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
                    while ($indices -contains $nextIndex) {
                        $nextIndex = ($nextIndex + 1) % $HighestIndex
                    }
                    $indices[$i] = $nextIndex
                }
                return $indices
            }
        }
        # Custom AES Galois/Counter Mode implementation
        class AesCrypt {
            static hidden [string] $caller
            static [ValidateNotNull()][EncryptionScope] $EncryptionScope
            static [byte[]] GetDerivedSalt([securestring]$password) {
                $rfc2898 = $null; $s4lt = $null; [byte[]]$s6lt = if ([AesCrypt]::EncryptionScope.ToString() -eq "Machine") {
                    [System.Text.Encoding]::UTF8.GetBytes([AesCrypt]::GetUniqueMachineId())
                } else {
                    [convert]::FromBase64String("qmkmopealodukpvdiexiianpnnutirid")
                }
                Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $password;
                Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $s6lt;
                Set-Variable -Name rfc2898 -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $s6lt));
                Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $($rfc2898.GetBytes(16));
                return $s4lt
            }
            static [byte[]] Encrypt([byte[]]$bytes) {
                return [AesCrypt]::Encrypt($bytes, [AesCrypt]::GetPassword());
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Encrypt($bytes, $Password, $_salt);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
                return [AesCrypt]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
            }
            static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
                return [convert]::ToBase64String([AesCrypt]::Encrypt([System.Text.Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
                return [AesCrypt]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
                return [AesCrypt]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
                return [AesCrypt]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
            }
            static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
                [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
                [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
                [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesCrypt]::GetString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
                [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesCrypt]::caller)) { [AesCrypt]::caller = '[AesCrypt]' }
                Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
                try {
                    $_bytes = $bytes;
                    $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
                    for ($i = 1; $i -lt $iterations + 1; $i++) {
                        # if ($Protect) { $_bytes = [xconvert]::ToProtected($_bytes, $Salt, [EncryptionScope]::User) }
                        # Generate a random IV for each iteration:
                        [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesCrypt]::GetString($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
                        $tag = [byte[]]::new($TAG_SIZE);
                        $Encrypted = [byte[]]::new($_bytes.Length);
                        [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
                        $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
                        Write-Debug "$([AesCrypt]::caller) [+] Encryption [$i/$iterations] ... Done"
                    }
                } catch {
                    throw $_
                } finally {
                    [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
                    Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
                }
                if (![string]::IsNullOrWhiteSpace($Compression)) {
                    $_bytes = [AesCrypt]::Compress($_bytes, $Compression);
                }
                return $_bytes
            }
            static [byte[]] Decrypt([byte[]]$bytes) {
                return [AesCrypt]::Decrypt($bytes, [AesCrypt]::GetPassword());
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Decrypt($bytes, $Password, $_salt);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
                return [AesCrypt]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
            }
            static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
                return [System.Text.Encoding]::UTF8.GetString([AesCrypt]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
                return [AesCrypt]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
                [byte[]]$_salt = [AesCrypt]::GetDerivedSalt($Password)
                return [AesCrypt]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
                return [AesCrypt]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
                return [AesCrypt]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
            }
            static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
                [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
                [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
                [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesCrypt]::GetString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
                [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesCrypt]::caller)) { [AesCrypt]::caller = '[AesCrypt]' }
                Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
                try {
                    $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { [AesCrypt]::DeCompress($bytes, $Compression) } else { $bytes }
                    $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
                    for ($i = 1; $i -lt $iterations + 1; $i++) {
                        # if ($UnProtect) { $_bytes = [xconvert]::ToUnProtected($_bytes, $Salt, [EncryptionScope]::User) }
                        # Split the real encrypted bytes from nonce & tags then decrypt them:
                ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                        $Decrypted = [byte[]]::new($b.Length);
                        $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                        $_bytes = $Decrypted;
                        Write-Debug "$([AesCrypt]::caller) [+] Decryption [$i/$iterations] ... Done"
                    }
                } catch {
                    if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                        Write-Host "$([AesCrypt]::caller) Wrong password" -ForegroundColor Yellow
                    }
                    throw $_
                } finally {
                    [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
                    Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
                }
                return $_bytes
            }
            static [byte[]] Compress([byte[]]$Bytes) {
                return [AesCrypt]::Compress($Bytes, 'Gzip');
            }
            static [string] Compress([string]$Plaintext) {
                return [convert]::ToBase64String([AesCrypt]::Compress([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
            }
            static [byte[]] Compress([byte[]]$Bytes, [string]$Compression) {
                if (("$Compression" -as 'Compression') -isnot 'Compression') {
                    Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([AesCrypt]) -join ', ')");
                }
                $outstream = [System.IO.MemoryStream]::new()
                $Comstream = switch ($Compression) {
                    "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
                    "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
                    "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
                    Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
                }
                [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
                [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
                return $OutPut;
            }
            static [byte[]] DeCompress([byte[]]$Bytes) {
                return [AesCrypt]::DeCompress($Bytes, 'Gzip');
            }
            static [string] DeCompress([string]$Base64Text) {
                return [System.Text.Encoding]::UTF8.GetString([AesCrypt]::DeCompress([convert]::FromBase64String($Base64Text)));
            }
            static [byte[]] DeCompress([byte[]]$Bytes, [string]$Compression) {
                if (("$Compression" -as 'Compression') -isnot 'Compression') {
                    Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
                }
                $inpStream = [System.IO.MemoryStream]::new($Bytes)
                $ComStream = switch ($Compression) {
                    "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
                    "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
                    "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
                    Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
                }
                $outStream = [System.IO.MemoryStream]::new();
                [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
                [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
                return $OutPut;
            }
            static [string] GetUniqueMachineId() {
                $Id = [string]($Env:MachineId)
                $vp = (Get-Variable VerbosePreference).Value
                try {
                    Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
                    $sha256 = [System.Security.Cryptography.SHA256]::Create()
                    $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
                    if ($HostOS -eq "Windows") {
                        if ([string]::IsNullOrWhiteSpace($Id)) {
                            $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                            Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineId))));
                        }
                        $Id = [string]($Env:MachineId)
                    } elseif ($HostOS -eq "Linux") {
                        # $Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
                        # Lets use mac addresses
                        $Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
                        $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
                    } elseif ($HostOS -eq "macOS") {
                        $Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
                        $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
                    } else {
                        throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
                    }
                } catch {
                    throw $_
                } finally {
                    $sha256.Clear(); $sha256.Dispose()
                    Set-Variable VerbosePreference -Value $vp
                }
                return $Id
            }
            static [SecureString] GetSecureString([string]$String) {
                $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
                if (![string]::IsNullOrEmpty($String)) {
                    $Chars = $String.toCharArray()
                    ForEach ($Char in $Chars) {
                        $SecureString.AppendChar($Char)
                    }
                }
                $SecureString.MakeReadOnly();
                return $SecureString
            }
            static [string] GetString([System.Security.SecureString]$SecureString) {
                [string]$Pstr = [string]::Empty;
                [IntPtr]$zero = [IntPtr]::Zero;
                if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
                    return [string]::Empty;
                }
                try {
                    Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
                    Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
                } finally {
                    if ($zero -ne [IntPtr]::Zero) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
                    }
                }
                return $Pstr;
            }
            static [securestring] GetPassword() {
                $_pass = if ([AesCrypt]::EncryptionScope.ToString() -eq "Machine") {
                    [AesCrypt]::GetSecureString([AesCrypt]::GetUniqueMachineId())
                } else {
                    Read-Host -Prompt "Password" -AsSecureString
                }
                return $_pass
            }
            static [void] ValidateCompression([string]$Compression) {
                if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") };
            }
        }
    }

    process {
        $content = [string]::Empty
        if ($PSBoundParameters.Count -eq 1) {
            if ([GitHub]::ParseLink($FileName, $false).Scheme.IsValid) {
                $PrsdUrl = [GitHub]::ParseLink($FileName, $false)
                if ($PrsdUrl.Scheme.IsGistUrl) {
                    $res = [GitHub]::GetGist([uri]::new($PrsdUrl.FullName))
                    Write-Verbose "[GitHub] Selecting first file in the gist"
                    $fn0 = ($res.files[0] | Get-Member -MemberType noteproperty).Name[0]
                    $content = $res.files.$fn0.content
                } else {
                    Write-Warning "Please Provide a valid Gist Url"
                }
            } else {
                $PSBoundParameters['GistUrl'] = $FileName
                $PSBoundParameters['FileName'] = [string]::Empty
            }
            Write-Verbose "fn : $FileName"
            Write-Verbose "gu : $GistUrl"
        } else {
            $content = [GitHub]::GetGistContent($FileName, [uri]::new($GistUrl))
        }
    }

    end {
        return $content
    }
}