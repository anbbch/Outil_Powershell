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

    if ($Max -le 0) {
        throw "La valeur Max doit être supérieure à 0."
    }

    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 4
    $randomNumberGenerator.GetBytes($bytes)
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

function Shuffle-Characters {
    param (
        [char[]]$Characters
    )

    $tempList = New-Object System.Collections.ArrayList
    foreach ($char in $Characters) {
        [void]$tempList.Add($char)
    }

    $shuffled = New-Object System.Collections.ArrayList

    while ($tempList.Count -gt 0) {
        $randomIndex = Get-SecureRandomIndex -Max $tempList.Count
        [void]$shuffled.Add($tempList[$randomIndex])
        $tempList.RemoveAt($randomIndex)
    }

    return -join $shuffled
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

    return (Shuffle-Characters -Characters $passwordChars)
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

function New-StrongPassword {
    param (
        [int]$Length = 7
    )

    if ($Length -lt 7) {
        $Length = 7
    }

    do {
        $Password = New-Password -Length $Length -Uppercase -Lowercase -Numbers -SpecialChars
        $analysis = Test-PasswordStrength -Password $Password
    } while ($analysis.Score -lt 5)

    return $Password
}

# ================================
# Étape 4 : Génération pour plusieurs utilisateurs
# ================================
function New-PasswordList {
    param (
        [string]$UserFile,
        [int]$Length = 7
    )

    if (-not (Test-Path $UserFile)) {
        throw "Le fichier $UserFile est introuvable."
    }

    if ($Length -lt 7) {
        $Length = 7
    }

    $users = Get-Content $UserFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($users.Count -eq 0) {
        throw "Le fichier $UserFile est vide."
    }

    $results = @()

    foreach ($user in $users) {
        $Password = New-StrongPassword -Length $Length
        $analysis = Test-PasswordStrength -Password $Password

        $results += [PSCustomObject]@{
            User     = $user
            Password = $Password
            Strength = $analysis.Strength
            Score    = $analysis.Score
        }
    }

    $Global:PasswordResults = $results
    return $results
}

function Write-PasswordsToSourceFile {
    param (
        [string]$UserFile
    )

    if (-not $Global:PasswordResults -or $Global:PasswordResults.Count -eq 0) {
        throw "Aucune donnée à écrire."
    }

    $lines = foreach ($item in $Global:PasswordResults) {
        "$($item.User) : $($item.Password)"
    }

    Set-Content -Path $UserFile -Value $lines -Encoding UTF8
    Write-Host "Les mots de passe ont été écrits dans le fichier source : $UserFile"
}

# ================================
# Étape 5 : Export CSV
# ================================
function Export-Passwords {
    param (
        [string]$Path
    )

    if (-not $Global:PasswordResults -or $Global:PasswordResults.Count -eq 0) {
        Write-Host "Aucun mot de passe à exporter."
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $downloads = Join-Path -Path $HOME -ChildPath "Downloads"
        $Path = Join-Path -Path $downloads -ChildPath "passwords.csv"
    }

    if (-not [System.IO.Path]::GetExtension($Path)) {
        $Path = Join-Path -Path $Path -ChildPath "passwords.csv"
    }

    $directory = Split-Path -Path $Path -Parent

    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
        Write-Host "Le dossier n'existe pas. Création du dossier..."
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    if (-not (Test-Path $Path)) {
        Write-Host "Le fichier n'existe pas. Création du fichier..."
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }

    $Global:PasswordResults |
        Select-Object User, Password, Strength, Score |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    Write-Host "Export réussi : $Path"
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
# Documentation
# ================================
function Show-Documentation {

    Write-Host ""
    Write-Host "================ DOCUMENTATION DU SCRIPT ================="
    Write-Host ""

    Write-Host "UTILISATION DES OPTIONS DU MENU"
    Write-Host "--------------------------------"
    Write-Host ""

    Write-Host "Option 1 : Générer un mot de passe"
    Write-Host "Génère un mot de passe sécurisé."
    Write-Host "Le mot de passe généré est aussi mémorisé pour pouvoir être exporté ensuite."
    Write-Host ""

    Write-Host "Option 2 : Tester la force d'un mot de passe"
    Write-Host "Analyse un mot de passe et retourne un score avec un niveau : Weak, Medium, Strong ou Very Strong."
    Write-Host ""

    Write-Host "Option 3 : Générer une liste de mots de passe"
    Write-Host "Le script lit un fichier contenant une liste d'utilisateurs."
    Write-Host "Il génère automatiquement un mot de passe pour chaque utilisateur présent dans le fichier."
    Write-Host "L'utilisateur choisit seulement la longueur des mots de passe."
    Write-Host "Ensuite, les résultats peuvent être affichés dans le terminal ou écrits dans le fichier source."
    Write-Host ""

    Write-Host "Option 4 : Exporter les mots de passe"
    Write-Host "Exporte les mots de passe mémorisés dans un fichier CSV."
    Write-Host "Si aucun chemin n'est donné, l'export se fait dans Downloads\passwords.csv."
    Write-Host ""

    Write-Host "Option 5 : Déposer au coffre-fort"
    Write-Host "Enregistre un mot de passe chiffré dans un fichier texte."
    Write-Host ""

    Write-Host "Option 6 : Documentation"
    Write-Host "Affiche l'aide du script."
    Write-Host ""

    Write-Host "Option 7 : Quitter"
    Write-Host "Ferme le programme."
    Write-Host ""

    Write-Host "FONCTIONS UTILISÉES"
    Write-Host "-------------------"
    Write-Host ""

    Write-Host "Get-SecureRandomIndex : génère un indice aléatoire sécurisé."
    Write-Host "Get-SecureRandomChar : récupère un caractère aléatoire sécurisé."
    Write-Host "Shuffle-Characters : mélange les caractères du mot de passe."
    Write-Host "New-Password : génère un mot de passe selon les critères demandés."
    Write-Host "Test-PasswordStrength : calcule le score et le niveau de robustesse."
    Write-Host "New-StrongPassword : garantit un mot de passe robuste avec une longueur minimale de 7."
    Write-Host "New-PasswordList : génère des mots de passe pour plusieurs utilisateurs."
    Write-Host "Write-PasswordsToSourceFile : écrit utilisateur : motdepasse dans le fichier source."
    Write-Host "Export-Passwords : exporte les résultats en CSV."
    Write-Host "Save-SecurePassword : chiffre et enregistre un mot de passe."
    Write-Host "Show-Menu : affiche le menu interactif."
    Write-Host ""
    Write-Host "==========================================================="
    Write-Host ""
}

# ================================
# Affichage des résultats
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
        Write-Host "6 - Documentation"
        Write-Host "7 - Quitter"
        Write-Host ""

        $choice = Read-Host "Choisissez une option"

        switch ($choice) {

            "1" {
                $Length = [int](Read-Host "Longueur du mot de passe")

                if ($Length -lt 7) {
                    Write-Host "La longueur minimale est 7. Elle sera fixée à 7."
                    $Length = 7
                }

                $Password = New-StrongPassword -Length $Length
                $analysis = Test-PasswordStrength -Password $Password

                $Global:PasswordResults = @(
                    [PSCustomObject]@{
                        User     = "Utilisateur_Simple"
                        Password = $Password
                        Strength = $analysis.Strength
                        Score    = $analysis.Score
                    }
                )

                Write-Host "Mot de passe généré : $Password"
            }

            "2" {
                $Password = Read-Host "Entrez le mot de passe à tester"
                $result = Test-PasswordStrength -Password $Password
                $result | Format-List
            }

            "3" {
                $UserFile = Read-Host "Chemin du fichier utilisateurs"
                $Length = [int](Read-Host "Longueur des mots de passe (minimum 7)")
            
                if ($Length -lt 7) {
                    Write-Host "La longueur choisie est inférieure à 7. Elle sera automatiquement fixée à 7."
                    $Length = 7
                }
            
                $results = New-PasswordList -UserFile $UserFile -Length $Length
            
                $displayChoice = Read-Host "Voulez-vous les afficher dans le terminal ? (O/N). Si vous tapez N, ils seront écrits dans le fichier source"
            
                if ($displayChoice -match "^[Oo]$") {
                    $results | Format-Table -AutoSize
                }
                else {
                    Write-PasswordsToSourceFile -UserFile $UserFile
                }
            }

            "4" {
                Write-Host "Appuyez sur Entrée pour enregistrer dans Downloads."
                $Path = Read-Host "Entrez un chemin d'enregistrement"

                Export-Passwords -Path $Path
            }

            "5" {
                $User = Read-Host "Nom de l'utilisateur"
                $Password = Read-Host "Mot de passe"
                $Path = Read-Host "Chemin du fichier coffre-fort (Entrée = secure_passwords.txt)"

                if ([string]::IsNullOrWhiteSpace($Path)) {
                    Save-SecurePassword -User $User -Password $Password
                }
                else {
                    Save-SecurePassword -User $User -Password $Password -Path $Path
                }
            }

            "6" {
                Show-Documentation
            }

            "7" {
                Write-Host "Fin du programme."
            }

            default {
                Write-Host "Option invalide."
            }
        }

    } while ($choice -ne "7")
}

# Lancement du menu
Show-Menu
