function Hello-World {
    Write-Host "Hello, World!"
}

function Xor-Encrypt {
    param (
        [string] $string,
        [string] $key
    )

    $keyLength = $key.Length
    $stringLength = $string.Length
    $encryptedString = ""

    for ($i = 0; $i -lt $stringLength; $i++) {
        $encryptedString += [char]($string[$i] -bxor $key[$i % $keyLength])
    }

    return $encryptedString
}

function Xor-Decrypt {
    param (
        [string] $string,
        [string] $key
    )

    $keyLength = $key.Length
    $stringLength = $string.Length
    $decryptedString = ""

    for ($i = 0; $i -lt $stringLength; $i++) {
        $decryptedString += [char]($string[$i] -bxor $key[$i % $keyLength])
    }

    return $decryptedString
}

Hello-World
$encrypted = Xor-Encrypt -string "Hello, World!" -key "key"
Write-Host $encrypted
$decrypted = Xor-Decrypt -string $encrypted -key "key"
Write-Host $decrypted

