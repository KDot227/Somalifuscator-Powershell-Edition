#python import type shi
. "$PSScriptRoot\util\strings\strings.ps1"
. "$PSScriptRoot\util\variables\variables.ps1"
. "$PSScriptRoot\util\commands\commands.ps1"
. "$PSScriptRoot\util\commands\function_names.ps1"
. "$PSScriptRoot\util\final\encodeOutput.ps1"
. "$PSScriptRoot\util\numbers\obfuscate_numbers.ps1"


$find = $false

#$IMPORTANT_COMMAND_REGEX = "\.[A-Za-z]+\("
#$safe_command_regex = "::[A-Za-z0-9]+\.[A-Za-z0-9]+"

$times = 0

function ObfuscateCode($code) {
    $code_copy = $code
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)


    #$StringConstantExpressionAst = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and ($args[0].StringConstantType -eq "DoubleQuoted" -or $args[0].StringConstantType -eq "SingleQuoted") }, $true)
    ##check if double quoted string
    #$StringConstantExpressionAst | ForEach-Object {
    #    $string = $_.Extent.Text
    #    $obfuscatedStringFull = ObfuscateString $string
    #    $code_copy = $code_copy -replace [regex]::Escape($string), $obfuscatedStringFull
    #}

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)

    $VariableExpressionAst = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    $VariableExpressionAst = $VariableExpressionAst | Select-Object -Unique
    $VariableExpressionAst | ForEach-Object {
        $variable = $_.Extent.Text
        $obfuscatedVariable = ObfuscateVariables $variable
        $variableAsString = [regex]::Escape($variable.ToString())
        $code_copy = $code_copy -replace $variableAsString, $obfuscatedVariable
    }

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)

    $functionNames = $ast.FindAll({ param([System.Management.Automation.Language.Ast] $Ast) $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

    # Function names only fr fr
    $functionNames | ForEach-Object { 
        $obfuscated = ObfuscateFunctionNames $_.Name
        $code_copy = $code_copy -replace [regex]::Escape($_.Name), $obfuscated
    }

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)

    #$StringConstantExpressionAst2 = $ast.FindAll({ ($args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $args[0].StringConstantType -eq "BareWord") -or ($args[0] -is [System.Management.Automation.Language.TypeExpressionAst]) }, $true)
    #$StringConstantExpressionAst2 | ForEach-Object {
    #    $string = $_.Extent.Text
    #    $obfuscatedStringFull = ObfuscateCommandTypes $string
    #    $code_copy = $code_copy -replace [regex]::Escape($string), $obfuscatedStringFull
    #}

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)

    $MethodOBF = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    $MethodOBF | ForEach-Object {
        $string = $_.Extent.Text
        if ($string.Contains(" ")) {
            $new_code = $string.split(" ")
            $string = $new_code[0]
        }

        $obfuscatedStringFull = ObfuscateMethodsGood $string
        $code_copy = $code_copy -replace [regex]::Escape($string), $obfuscatedStringFull
    } 

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)

    #$NumberOBF = $ast.FindAll({ ($args[0] -is [System.Management.Automation.Language.ConstantExpressionAst]) -and ($args[0].StaticType -eq [System.Int32]) }, $true)
    #$NumberOBF | ForEach-Object {
    #    $number = $_.Extent.Text
    #    Write-Host $number
    #    $obfuscatedStringFull = AddOrSubtractRandomEQ $number
    #    $code_copy = $code_copy -replace [regex]::Escape($number), $obfuscatedStringFull
    #}

    if ($find) {
        if (Test-Path "ast.txt") {
            Remove-Item "ast.txt"
        }
        $ast.FindAll({ $true }, $true) | ForEach-Object {
            $_.GetType().Name | Out-File "ast.txt" -Append
            $_ | Format-List | Out-String | Out-File "ast.txt" -Append
            "====================================================================================================================" | Out-File "ast.txt" -Append
        }
    }
    return $code_copy
}

function Encrypt-Payload($string_payload) {
    $placeholder_code = @"
function Create-AesManagedObject(`$key, `$IV, `$mode) {`$aesManaged = New-Object "System.Security.Cryptography.AesManaged";if (`$mode="CBC") { `$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC }elseif (`$mode="CFB") {`$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CFB}elseif (`$mode="CTS") {`$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CTS}elseif (`$mode="ECB") {`$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB}elseif (`$mode="OFB"){`$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::OFB};`$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;`$aesManaged.BlockSize = 128;`$aesManaged.KeySize = 256;if (`$IV) {if (`$IV.getType().Name -eq "String") {`$aesManaged.IV = [System.Convert]::FromBase64String(`$IV)}else {`$aesManaged.IV = `$IV}};if (`$key) {if (`$key.getType().Name -eq "String") {`$aesManaged.Key = [System.Convert]::FromBase64String(`$key)}else {`$aesManaged.Key = `$key}};return `$aesManaged};function Decrypt-String(`$key, `$encryptedStringWithIV) {`$bytes = [System.Convert]::FromBase64String(`$encryptedStringWithIV);`$IV = `$bytes[0..15];`$aesManaged = Create-AesManagedObject `$key `$IV;`$decryptor = `$aesManaged.CreateDecryptor();;`$unencryptedData = `$decryptor.TransformFinalBlock(`$bytes, 16, `$bytes.Length - 16);;`$aesManaged.Dispose();return [System.Text.Encoding]::UTF8.GetString(`$unencryptedData).Trim([char]0)};iex(Decrypt-String "YOUR_KEY_HERE" "YOUR_ENCRYPTED_STRING_HERE")
"@
    $key = Create-AesKey
    $encryptedString = Encrypt-String $key $string_payload
    $new_code1 = $placeholder_code -replace "YOUR_KEY_HERE", $key
    $final_code = $new_code1 -replace "YOUR_ENCRYPTED_STRING_HERE", $encryptedString
    return $final_code
}

function Main($payload) {
    $obfuscatedCode = ObfuscateCode $payload
    if ($times -ne 0) {
        while ($times -ne 1) {
            $times = $times - 1
            $obfuscatedCode = Encrypt-Payload $obfuscatedCode
            $obfuscatedCode = ObfuscateCode $obfuscatedCode
        }
    }

    return $obfuscatedCode
}



#ObfuscateCode "example\test.ps1" | Out-File "example\out.ps1" -Forc

$stuff = Get-Content "example\test.ps1" -Raw

$obfuscatedCode = Main $stuff
$obfuscatedCode | Out-File "example\out.ps1" -Force