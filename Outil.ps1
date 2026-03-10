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
        [int]$Length = 7,
        [int]$Count
    )

    if (-not (Test-Path $UserFile)) {
        throw "Le fichier $UserFile est introuvable."
    }

    if ($Length -lt 7) {
        $Length = 7
    }

    $users = Get-Content $UserFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($Count -gt $users.Count) {
        throw "Le fichier contient seulement $($users.Count) utilisateur(s)."
    }

    $results = @()

    for ($i = 0; $i -lt $Count; $i++) {
        $user = $users[$i]
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

    # Si l'utilisateur appuie sur Entrée → Downloads
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $downloads = Join-Path $HOME "Downloads"
        $Path = Join-Path $downloads "passwords.csv"
    }

    # Si l'utilisateur donne seulement un dossier
    if (-not [System.IO.Path]::GetExtension($Path)) {
        $Path = Join-Path $Path "passwords.csv"
    }

    # Vérifier si le dossier existe
    $directory = Split-Path $Path -Parent

    if (-not (Test-Path $directory)) {
        Write-Host "Le dossier n'existe pas. Création du dossier..."
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    # Si le fichier n'existe pas → création
    if (-not (Test-Path $Path)) {
        Write-Host "Le fichier n'existe pas. Création du fichier..."
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }

    # Export CSV
    $Global:PasswordResults |
        Select-Object User, Password |
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

function Show-Documentation {

    Write-Host ""
    Write-Host "================ DOCUMENTATION DU SCRIPT ================="
    Write-Host ""

    Write-Host "UTILISATION DES OPTIONS DU MENU"
    Write-Host "--------------------------------"

    Write-Host "Option 1 : Générer un mot de passe"
    Write-Host "Permet de générer un mot de passe sécurisé."
    Write-Host "L'utilisateur choisit la longueur du mot de passe."
    Write-Host "Le mot de passe contient des majuscules, minuscules, chiffres et caractères spéciaux."
    Write-Host ""

    Write-Host "Option 2 : Tester la force d'un mot de passe"
    Write-Host "Permet d'analyser la robustesse d'un mot de passe."
    Write-Host "Le script attribue un score et indique si le mot de passe est : Weak, Medium, Strong ou Very Strong."
    Write-Host ""

    Write-Host "Option 3 : Générer une liste de mots de passe"
    Write-Host "Permet de générer automatiquement un mot de passe pour plusieurs utilisateurs."
    Write-Host "Le script lit un fichier contenant une liste d'utilisateurs."
    Write-Host "Chaque utilisateur reçoit un mot de passe sécurisé."
    Write-Host ""

    Write-Host "Option 4 : Exporter les mots de passe"
    Write-Host "Permet d'exporter les mots de passe générés dans un fichier CSV."
    Write-Host "Le fichier peut ensuite être ouvert avec Excel."
    Write-Host ""

    Write-Host "Option 5 : Déposer au coffre-fort"
    Write-Host "Permet d'enregistrer un mot de passe de manière sécurisée."
    Write-Host "Le mot de passe est chiffré avec SecureString avant d'être stocké."
    Write-Host ""

    Write-Host ""
    Write-Host "FONCTIONS UTILISÉES DANS LE SCRIPT"
    Write-Host "-----------------------------------"
    Write-Host ""

    Write-Host "Get-SecureRandomIndex"
    Write-Host "Cette fonction génère un nombre aléatoire sécurisé."
    Write-Host "Elle utilise RandomNumberGenerator de .NET au lieu de Get-Random."
    Write-Host "Elle permet de choisir un indice aléatoire dans une liste de caractères."
    Write-Host ""

    Write-Host "Get-SecureRandomChar"
    Write-Host "Cette fonction sélectionne un caractère aléatoire sécurisé dans une chaîne."
    Write-Host "Elle utilise Get-SecureRandomIndex pour déterminer la position du caractère."
    Write-Host ""

    Write-Host "New-Password"
    Write-Host "Cette fonction génère un mot de passe sécurisé."
    Write-Host "Elle garantit qu'il contient différents types de caractères."
    Write-Host "Elle utilise RandomNumberGenerator pour améliorer la sécurité."
    Write-Host ""

    Write-Host "Test-PasswordStrength"
    Write-Host "Cette fonction analyse la robustesse d'un mot de passe."
    Write-Host "Elle vérifie :"
    Write-Host "- la longueur"
    Write-Host "- les majuscules"
    Write-Host "- les minuscules"
    Write-Host "- les chiffres"
    Write-Host "- les caractères spéciaux"
    Write-Host "Elle calcule ensuite un score."
    Write-Host ""

    Write-Host "New-PasswordList"
    Write-Host "Cette fonction lit un fichier contenant des utilisateurs."
    Write-Host "Elle génère un mot de passe pour chacun d'eux."
    Write-Host "Les résultats sont stockés dans une variable globale."
    Write-Host ""

    Write-Host "Export-Passwords"
    Write-Host "Cette fonction exporte les mots de passe dans un fichier CSV."
    Write-Host "Elle utilise la commande PowerShell Export-Csv."
    Write-Host ""

    Write-Host "Save-SecurePassword"
    Write-Host "Cette fonction stocke un mot de passe dans un coffre-fort."
    Write-Host "Le mot de passe est converti en SecureString puis chiffré."
    Write-Host ""

    Write-Host "Show-Menu"
    Write-Host "Cette fonction affiche le menu interactif."
    Write-Host "Elle permet à l'utilisateur de choisir les différentes options du script."
    Write-Host ""

    Write-Host "==========================================================="
    Write-Host ""
}

# ================================
# Étape 7 : Menu interactif
# ================================
function Show-Results {
    if ($Global:PasswordResults -and $Global:PasswordResults.Count -gt 0) {
        $Global:PasswordResults | Format-Table -AutoSize
    }
    else {
        Write-Host "Aucun résultat disponible."
    }
}

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
                Write-Host "Appuyez sur Entrée pour enregistrer dans Downloads."
                $Path = Read-Host "Entrez un chemin d'enregistrement"
                Export-Passwords -Path $Path
            }

            "5" {
                $User = Read-Host "Nom de l'utilisateur"
                $Password = Read-Host "Mot de passe"
                Save-SecurePassword -User $User -Password $Password
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
