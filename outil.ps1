# ================================
# Variables globales
# ================================
$Global:PasswordResults = @()

# ================================
# Étape 1 + 2 : Génération sécurisée
# ================================
function Get-SecureRandomIndex {
    param (
        [int]$Max
    )

    $randomNumber = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 4
    $randomNumber.GetBytes($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)

    return $value % $Max
}

function Get-SecureRandomChar {
    param (
        [string]$Characters
    )

    $index = Get-SecureRandomIndex -Max $Characters.Length
    return $Characters[$index]
}

function New-Password {
    param (
        [int]$Length = 16,
        [switch]$Uppercase,
        [switch]$Lowercase,
        [switch]$Numbers,
        [switch]$SpecialChars
    )

    if (-not $Uppercase -and -not $Lowercase -and -not $Numbers -and -not $SpecialChars) {
        $Uppercase = $true
        $Lowercase = $true
        $Numbers = $true
        $SpecialChars = $true
    }

    $upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowerChars = "abcdefghijklmnopqrstuvwxyz"
    $numberChars = "0123456789"
    $specialCharsSet = "!@#$%^&*()-_=+[]{};:,.?/"

    $allChars = ""
    $requiredChars = @()

    if ($Uppercase) {
        $allChars += $upperChars
        $requiredChars += (Get-SecureRandomChar -Characters $upperChars)
    }

    if ($Lowercase) {
        $allChars += $lowerChars
        $requiredChars += (Get-SecureRandomChar -Characters $lowerChars)
    }

    if ($Numbers) {
        $allChars += $numberChars
        $requiredChars += (Get-SecureRandomChar -Characters $numberChars)
    }

    if ($SpecialChars) {
        $allChars += $specialCharsSet
        $requiredChars += (Get-SecureRandomChar -Characters $specialCharsSet)
    }

    if ($Length -lt $requiredChars.Count) {
        throw "La longueur doit être au moins égale au nombre de groupes de caractères sélectionnés."
    }

    $passwordChars = @()
    $passwordChars += $requiredChars

    for ($i = $passwordChars.Count; $i -lt $Length; $i++) {
        $passwordChars += (Get-SecureRandomChar -Characters $allChars)
    }

    # Mélange sécurisé final
    $shuffledPassword = @()
    while ($passwordChars.Count -gt 0) {
        $randomIndex = Get-SecureRandomIndex -Max $passwordChars.Count
        $shuffledPassword += $passwordChars[$randomIndex]
        $passwordChars = $passwordChars | Where-Object { $_ -ne $passwordChars[$randomIndex] } | Select-Object -First ($passwordChars.Count - 1)
    }

    return (-join $shuffledPassword)
}

# ================================
# Étape 3 : Vérification de robustesse
# ================================
function Test-PasswordStrength {
    param (
        [string]$Password
    )

    $score = 0

    if ($Password.Length -ge 12) {
        $score += 2
    }

    if ($Password -match "[A-Z]") {
        $score += 1
    }

    if ($Password -match "[a-z]") {
        $score += 1
    }

    if ($Password -match "[0-9]") {
        $score += 1
    }

    if ($Password -match "[^a-zA-Z0-9]") {
        $score += 2
    }

    if ($Password -match "(.)\1") {
        $score -= 1
    }

    $strength = switch ($score) {
        { $_ -le 2 } { "Weak" }
        { $_ -le 4 } { "Medium" }
        { $_ -le 6 } { "Strong" }
        default      { "Very Strong" }
    }

    return [PSCustomObject]@{
        Password = $Password
        Score    = $score
        Strength = $strength
    }
}

# ================================
# Étape 4 : Génération pour plusieurs utilisateurs
# ================================
function New-PasswordList {
    param (
        [string]$UserFile,
        [int]$Length = 14
    )

    if (-not (Test-Path $UserFile)) {
        throw "Le fichier $UserFile est introuvable."
    }

    $users = Get-Content $UserFile
    $results = @()

    foreach ($user in $users) {
        if (-not [string]::IsNullOrWhiteSpace($user)) {
            $Password = New-Password -Length $Length -Uppercase -Lowercase -Numbers -SpecialChars
            $analysis = Test-PasswordStrength -Password $Password

            $results += [PSCustomObject]@{
                User     = $user
                Password = $Password
                Strength = $analysis.Strength
                Score    = $analysis.Score
            }
        }
    }

    $Global:PasswordResults = $results
    return $results
}

# ================================
# Étape 5 : Export CSV
# ================================
function Export-Passwords {
    param (
        [string]$Path
    )

    if (-not $Global:PasswordResults -or $Global:PasswordResults.Count -eq 0) {
        throw "Aucune donnée à exporter."
    }

    $Global:PasswordResults | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Host "Export effectué vers : $Path"
}

# ================================
# Étape 6 : Coffre-fort sécurisé
# ================================
function Save-SecurePassword {
    param (
        [string]$User,
        [string]$Password,
        [string]$Path = "secure_passwords.txt"
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $encryptedPassword = ConvertFrom-SecureString $securePassword

    "$User;$encryptedPassword" | Add-Content -Path $Path
    Write-Host "Mot de passe sécurisé enregistré pour $User dans $Path"
}

# ================================
# Fonction utilitaire d'affichage
# ================================
function Show-Results {
    if ($Global:PasswordResults -and $Global:PasswordResults.Count -gt 0) {
        $Global:PasswordResults | Format-Table -AutoSize
    }
    else {
        Write-Host "Aucun résultat disponible."
    }
}

# ================================
# Étape 7 : Menu interactif
# ================================
function Show-Menu {
    do {
        Write-Host ""
        Write-Host "===== Générateur et gestionnaire de mots de passe sécurisé ====="
        Write-Host "1 - Générer un mot de passe"
        Write-Host "2 - Tester la force d'un mot de passe"
        Write-Host "3 - Générer une liste de mots de passe"
        Write-Host "4 - Exporter les mots de passe"
        Write-Host "5 - Déposer au coffre-fort"
        Write-Host "6 - Quitter"
        Write-Host ""

        $choice = Read-Host "Choisissez une option"

        switch ($choice) {
            "1" {
                $Length = [int](Read-Host "Longueur du mot de passe")
                $Password = New-Password -Length $Length -Uppercase -Lowercase -Numbers -SpecialChars
                Write-Host "Mot de passe généré : $Password"
            }

            "2" {
                $Password = Read-Host "Entrez le mot de passe à tester"
                $result = Test-PasswordStrength -Password $Password
                $result | Format-List
            }

            "3" {
                $UserFile = Read-Host "Chemin du fichier utilisateurs"
                $Length = [int](Read-Host "Longueur des mots de passe")
                $results = New-PasswordList -UserFile $UserFile -Length $Length
                $results | Format-Table -AutoSize
            }

            "4" {
                $Path = Read-Host "Chemin du fichier CSV"
                Export-Passwords -Path $Path
            }

            "5" {
                $User = Read-Host "Nom de l'utilisateur"
                $Password = Read-Host "Mot de passe à sécuriser"
                $Path = Read-Host "Chemin du fichier coffre-fort (Entrée = secure_passwords.txt)"

                if ([string]::IsNullOrWhiteSpace($Path)) {
                    Save-SecurePassword -User $User -Password $Password
                }
                else {
                    Save-SecurePassword -User $User -Password $Password -Path $Path
                }
            }

            "6" {
                Write-Host "Fin du programme."
            }

            default {
                Write-Host "Option invalide."
            }
        }

    } while ($choice -ne "6")
}

# Lancement du menu
Show-Menu
