#python import type shi
. "$PSScriptRoot\util\strings\strings.ps1"
. "$PSScriptRoot\util\variables\variables.ps1"
. "$PSScriptRoot\util\commands\commands.ps1"
. "$PSScriptRoot\util\commands\function_names.ps1"
. "$PSScriptRoot\util\final\encodeOutput.ps1"
. "$PSScriptRoot\util\numbers\obfuscate_numbers.ps1"

$times = 0
$verbose = $false

# this is EXTREMELY NEEDED because the Get-Command function is so utterly slow.
$CommandTypeCache = @{}

function ObfuscateCode($code) {
    $code_copy = $code
    $functionReplacementMap = @{}
    $variableReplacementMap = @{}
    $parameterReplacementMap = @{}
    $stringReplacementMap = @{}
    $barewordReplacementMap = @{}
    $numberReplacementMap = @{}

    $comments = [System.Management.Automation.PSParser]::Tokenize($code_copy, [ref]$null) | Where-Object { $_.Type -eq "Comment" }
    foreach ($comment in $comments) {
        $code_copy = $code_copy.Replace($comment.Content, "")
    }
    
    # first pass - handle everything except barewords
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)
    
    # get all function definitions
    $functionDefinitions = $ast.FindAll({ param([System.Management.Automation.Language.Ast] $Ast) 
        $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    
    # get all command calls
    $allCommandCalls = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    
    # get all variable expressions
    $variableExpressions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    
    # get all parameter ASTs
    $parameterAsts = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true)

    $stringAsts = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and ($args[0].StringConstantType -eq "DoubleQuoted" -or $args[0].StringConstantType -eq "SingleQuoted") }, $true)

    foreach ($func in $functionDefinitions) {
        if (-not $functionReplacementMap.ContainsKey($func.Name)) {
            $functionReplacementMap[$func.Name] = ObfuscateFunctionNames $func.Name
        }
        
        # handle parameters in function definition
        if ($func.Parameters) {
            foreach ($param in $func.Parameters) {
                $paramName = $param.Name.VariablePath.UserPath
                if (-not $parameterReplacementMap.ContainsKey($paramName)) {
                    $newParamName = ObfuscateVariables $paramName
                    $parameterReplacementMap[$paramName] = $newParamName.TrimStart('$')
                    $variableReplacementMap[$paramName] = $newParamName
                }
            }
        }
        if ($func.Body.ParamBlock) {
            foreach ($param in $func.Body.ParamBlock.Parameters) {
                $paramName = $param.Name.VariablePath.UserPath
                if (-not $parameterReplacementMap.ContainsKey($paramName)) {
                    $newParamName = ObfuscateVariables $paramName
                    $parameterReplacementMap[$paramName] = $newParamName.TrimStart('$')
                    $variableReplacementMap[$paramName] = $newParamName
                }
            }
        }
    }
    
    # process regular variables
    foreach ($var in $variableExpressions) {
        $varName = $var.VariablePath.UserPath
        if (-not $variableReplacementMap.ContainsKey($varName) -and -not $parameterReplacementMap.ContainsKey($varName)) {
            $variableReplacementMap[$varName] = ObfuscateVariables $var.Extent.Text
        }
    }
    
    $allReplacements = @()
    
    # add function definitions
    foreach ($func in $functionDefinitions) {
        $functionKeywordLength = "function ".Length
        $actualStartOffset = $func.Extent.StartOffset + $functionKeywordLength
        
        $allReplacements += @{
            StartOffset = $actualStartOffset
            Length = $func.Name.Length
            OriginalName = $func.Name
            Text = $func.Name
            Type = "Function"
        }
    }
    
    # add function calls and parameters
    foreach ($call in $allCommandCalls) {
        $commandName = $call.CommandElements[0].Extent.Text
        if ($functionReplacementMap.ContainsKey($commandName)) {
            $allReplacements += @{
                StartOffset = $call.CommandElements[0].Extent.StartOffset
                Length = $commandName.Length
                OriginalName = $commandName
                Text = $commandName
                Type = "Function"
            }
            
            for ($i = 1; $i -lt $call.CommandElements.Count; $i++) {
                $element = $call.CommandElements[$i]
                if ($element.Extent.Text.StartsWith('-')) {
                    $paramName = $element.Extent.Text.TrimStart('-')
                    if ($parameterReplacementMap.ContainsKey($paramName)) {
                        $allReplacements += @{
                            StartOffset = $element.Extent.StartOffset
                            Length = $element.Extent.Text.Length
                            OriginalName = $paramName
                            Text = "-" + $paramName
                            Type = "ParameterName"
                        }
                    }
                }
            }
        }
    }
    
    # add variables
    foreach ($var in $variableExpressions) {
        $varName = $var.VariablePath.UserPath
        $parent = $var.Parent
        $isParameterName = $false
        while ($parent) {
            if ($parent -is [System.Management.Automation.Language.CommandAst]) {
                $isParameterName = $parent.CommandElements | Where-Object { $_.Extent.Text -eq "-$($var.Extent.Text)" }
                if ($isParameterName) { break }
            }
            $parent = $parent.Parent
        }
        
        if (-not $isParameterName) {
            $allReplacements += @{
                StartOffset = $var.Extent.StartOffset
                Length = $var.Extent.Text.Length
                OriginalName = $varName
                Text = $var.Extent.Text
                Type = "Variable"
            }
        }
    }

    # add strings
    foreach ($string in $stringAsts) {
        $stringText = $string.Extent.Text
        
        # handle empty strings
        if ([string]::IsNullOrWhiteSpace($stringText) -or $stringText -eq '""' -or $stringText -eq "''") {
            $allReplacements += @{
                StartOffset = $string.Extent.StartOffset
                Length = $string.Extent.Text.Length
                OriginalName = $stringText
                Text = $string.Extent.Text
                Type = "EmptyString"
                NewName = '[string]::Empty'
            }
            continue
        }

        # check to see if string only contains single or double quotes inside. (if example: "''" or "''''") if the string is empty then just keep going.
        if ($stringText -match "^['""]+$") {
            $allReplacements += @{
                StartOffset = $string.Extent.StartOffset
                Length = $string.Extent.Text.Length
                OriginalName = $stringText
                Text = $string.Extent.Text
                Type = "EmptyString"
                NewName = '[string]::Empty'
            }
            continue
        }

        # handle normal strings
        if ($string.Extent.Text.Length -lt 3) { continue }
        if (-not $stringReplacementMap.ContainsKey($stringText)) {
            $stringReplacementMap[$stringText] = ObfuscateString $stringText
        }
        
        $allReplacements += @{
            StartOffset = $string.Extent.StartOffset
            Length = $string.Extent.Text.Length
            OriginalName = $stringText
            Text = $string.Extent.Text
            Type = "String"
        }
    }
    
    # first pass replacements
    $allReplacements = $allReplacements | Sort-Object { $_.StartOffset } -Descending
    
    foreach ($replacement in $allReplacements) {
        $newName = switch ($replacement.Type) {
            "Function" { $functionReplacementMap[$replacement.OriginalName] }
            "ParameterName" { "-" + $parameterReplacementMap[$replacement.OriginalName] }
            "Variable" { $variableReplacementMap[$replacement.OriginalName] }
            "String" { $stringReplacementMap[$replacement.OriginalName] }
            "EmptyString" { $replacement.NewName }
        }
        
        Write-Host "First Pass - Replacing '$($replacement.Text)' at position $($replacement.StartOffset) with '$newName' (Type: $($replacement.Type))"
        
        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $newName
    }

    $newAst = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)
    $barewordAsts = $newAst.FindAll({ ($args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $args[0].StringConstantType -eq "BareWord") -or ($args[0] -is [System.Management.Automation.Language.TypeExpressionAst]) }, $true)
    
    $barewordReplacements = @()
    
    foreach ($bareword in $barewordAsts) {
        if ($bareword.Extent.Text.Length -lt 3) { continue }
        if ($functionReplacementMap.ContainsKey($bareword.Extent.Text)) { continue }
        
        # get command type information
        $commandInfo = Get-CommandType -CommandName $bareword.Extent.Text
        
        # generate a new random replacement for each instance
        # pass the command info to ObfuscateCommandTypes
        $newBarewordName = ObfuscateCommandTypes -CommandText $bareword.Extent.Text -CommandInfo $commandInfo
        
        $barewordReplacements += @{
            StartOffset = $bareword.Extent.StartOffset
            Length = $bareword.Extent.Text.Length
            OriginalName = $bareword.Extent.Text
            Text = $bareword.Extent.Text
            NewName = $newBarewordName
            Type = "Bareword"
            CommandType = $commandInfo.Type
            IsBuiltIn = $commandInfo.IsBuiltIn
        }
    }

    # second pass replacements
    $barewordReplacements = $barewordReplacements | Sort-Object { $_.StartOffset } -Descending
    
    foreach ($replacement in $barewordReplacements) {
        Write-Host "Second Pass - Replacing bareword '$($replacement.Text)' at position $($replacement.StartOffset) with '$($replacement.NewName)'"
        
        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $replacement.NewName
    }
    
    return $code_copy
}

function Replace-TextAtPosition {
    param(
        [string]$SourceText,
        [int]$StartPosition,
        [int]$Length,
        [string]$ReplacementText
    )
    
    try {
        $before = $SourceText.Substring(0, $StartPosition)
        $after = $SourceText.Substring($StartPosition + $Length)
        return $before + $ReplacementText + $after
    }
    catch {
        Write-Host "Error in Replace-TextAtPosition:"
        Write-Host "Source length: $($SourceText.Length)"
        Write-Host "Start: $StartPosition"
        Write-Host "Length: $Length"
        Write-Host "Replacement: $ReplacementText"
        throw $_
    }
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

function Get-CommandType {
    param(
        [string]$CommandName
    )

    # simple cache because Get-Command is slow ash
    if ($CommandTypeCache.ContainsKey($CommandName)) {
        return $CommandTypeCache[$CommandName]
    }

    $command = Get-Command -Name $CommandName -ErrorAction Ignore
    
    $result = if ($command) {
        @{
            IsBuiltIn = $true
            Type = $command.CommandType
            Name = $CommandName
        }
    } else {
        @{
            IsBuiltIn = $false
            Type = "Unknown"
            Name = $CommandName
        }
    }

    # Cache the result for future calls
    $CommandTypeCache[$CommandName] = $result
    return $result
}

function Main($payload) {
    $obfuscatedCode = ObfuscateCode $payload
    if ($times -ne 0) {
        $totalSteps = ($times * 2) + 1
        $currentStep = 0
        while ($times -ne 1) {
            $times = $times - 1
            $obfuscatedCode = Encrypt-Payload $obfuscatedCode 
            $currentStep++
            Write-Progress -Activity "Obfuscating Code" -Status "Encrypting Payload" -PercentComplete (($currentStep / $totalSteps) * 100)
            $obfuscatedCode = ObfuscateCode $obfuscatedCode
            $currentStep++
            Write-Progress -Activity "Obfuscating Code" -Status "Obfuscating Code" -PercentComplete (($currentStep / $totalSteps) * 100)
        }
    }

    Write-Progress -Activity "Obfuscating Code" -Status "Completed" -PercentComplete 100 -Completed
    return $obfuscatedCode
}

$file_location = Read-Host "Enter the file location -> "
$stuff = Get-Content $file_location -Raw

$obfuscatedCode = Main $stuff
$obfuscatedCode | Out-File "example\out.ps1" -Force