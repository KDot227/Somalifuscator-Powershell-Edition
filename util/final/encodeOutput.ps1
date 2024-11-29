# Taken from https://gist.github.com/ctigeek/2a56648b923d198a6e60

function Create-AesManagedObject($key, $IV, $mode) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"

    if ($mode="CBC") { $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC }
    elseif ($mode="CFB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CFB}
    elseif ($mode="CTS") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CTS}
    elseif ($mode="ECB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB}
    elseif ($mode="OFB"){$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::OFB}


    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    return $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    return [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $aesManaged.Dispose()
    return [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

#$key = Create-AesKey
#
#
#$plaintext =  "This is a test string"
#$mode =  "OFB"
#"== Powershell AES $mode Encyption=="
#"`nKey: "+$key
#
#$encryptedString = Encrypt-String $key $plaintext
#
#$bytes = [System.Convert]::FromBase64String($encryptedString)
#
#$IV = $bytes[0..15]
#"Salt: " +  [System.Convert]::ToHexString($IV)
#"Salt: " +  [System.Convert]::ToBase64String($IV)
#
#$plain = Decrypt-String $key $encryptedString
#
#"`nEncrypted: "+$encryptedString 
#
#"Decrypted: "+$plain

function Encrypt-Payload($string_payload) {
    $placeholder_code = @"
function Decrypt-String(`$key, `$encryptedStringWithIV) {`$bytes = [System.Convert]::FromBase64String(`$encryptedStringWithIV);`$IV = `$bytes[0..15];`$aesManaged = Create-AesManagedObject `$key `$IV;`$decryptor = `$aesManaged.CreateDecryptor();;`$unencryptedData = `$decryptor.TransformFinalBlock(`$bytes, 16, `$bytes.Length - 16);;`$aesManaged.Dispose();return [System.Text.Encoding]::UTF8.GetString(`$unencryptedData).Trim([char]0)};iex(Decrypt-String "YOUR_KEY_HERE" "YOUR_ENCRYPTED_STRING_HERE")
"@
    $key = Create-AesKey
    $encryptedString = Encrypt-String $key $string_payload
    $placeholder_code -replace "YOUR_KEY_HERE", $key
    $placeholder_code -replace "YOUR_ENCRYPTED_STRING_HERE", $encryptedString
    return $placeholder_code
}

$placeholder_code -replace "YOUR_KEY_HERE" | Out-Null