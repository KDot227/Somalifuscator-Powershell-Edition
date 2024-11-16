#python import type shi
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

. "$scriptPath\util\strings\strings.ps1"
. "$scriptPath\util\variables\variables.ps1"
. "$scriptPath\util\commands\commands.ps1"
. "$scriptPath\util\commands\function_names.ps1"
. "$scriptPath\util\final\encodeOutput.ps1"
. "$scriptPath\util\numbers\obfuscate_numbers.ps1"
. "$scriptPath\util\wrap\wrap.ps1"
. "$scriptPath\util\MBA_OBF\mixed_boolean_arithmetic.ps1"

$global:pass_number = 1

$times_wrap = 2
$verbose = $false
$verbose_out_file = $false
$mba_depth = 2

if ($verbose_out_file) {
    #redirect standard output when we need the verbose in a file
    $VerbosePreference = "Continue"
    $date_and_time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $VerboseOutput = "obfuscate$date_and_time.log"
    Start-Transcript -Path $VerboseOutput
}

# this is EXTREMELY NEEDED because the Get-Command function is so utterly slow.
$CommandTypeCache = @{}

$functionNamesIgnore = @("CheckValidationResult")

$built_in_aliases = @('foreach', 'where', 'clc', 'cli', 'clp', 'clv', 'cpi', 'cvpa', 'dbp', 'ebp', 'epal',
    'epcsv', 'fl', 'ft', 'fw', 'gal', 'gbp', 'gc', 'gci', 'gcm', 'gdr', 'gcs', 'ghy', 'gi', 'gl', 'gm', 'gmo', 'gp',
    'gpv', 'gps', 'group', 'gu', 'gv', 'iex', 'ihy', 'ii', 'ipmo', 'ipal', 'ipcsv', 'measure', 'mi', 'mp', 'nal',
    'ndr', 'ni', 'nv', 'nmo', 'oh', 'rbp', 'rdr', 'ri', 'rni', 'rnp', 'rp', 'rmo', 'rv', 'gerr', 'rvpa', 'sal',
    'sbp', 'select', 'si', 'sl', 'sp', 'saps', 'spps', 'sv', 'irm', 'iwr', 'ac', 'clear', 'compare', 'cpp', 'diff',
    'gsv', 'sleep', 'sort', 'start', 'sasv', 'spsv', 'tee', 'write', 'cat', 'cp', 'ls', 'man', 'mount', 'mv', 'ps',
    'rm', 'rmdir', 'cnsn', 'dnsn', 'ogv', 'shcm', 'cd', 'dir', 'echo', 'fc', 'kill', 'pwd', 'type', 'h', 'history',
    'md', 'popd', 'pushd', 'r', 'cls', 'chdir', 'copy', 'del', 'erase', 'move', 'rd', 'ren', 'set', 'icm', 'clhy',
    'gjb', 'rcjb', 'rjb', 'sajb', 'spjb', 'wjb', 'nsn', 'gsn', 'rsn', 'etsn', 'rcsn', 'exsn', 'sls')

function ObfuscateCode($code) {
    $code_copy = $code
    $functionReplacementMap = @{}
    $variableReplacementMap = @{}
    $parameterReplacementMap = @{}
    $stringReplacementMap = @{}
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

    $stringAsts = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and ($args[0].StringConstantType -eq "DoubleQuoted" -or $args[0].StringConstantType -eq "SingleQuoted") }, $true)

    $numberAsts = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ConstantExpressionAst] -and $args[0].StaticType.Name -eq "Int32" }, $true)

    # Process function definitions and create replacement map
    foreach ($func in $functionDefinitions) {
        if (-not $functionReplacementMap.ContainsKey($func.Name)) {
            $functionReplacementMap[$func.Name] = ObfuscateFunctionNames $func.Name
        }

        # handle parameters in function definition
        if ($func.Parameters) {
            foreach ($param in $func.Parameters) {
                $paramName = $param.Name.VariablePath.UserPath
                if (-not $parameterReplacementMap.ContainsKey($paramName)) {
                    $newParamName = ObfuscateVariables $paramName $true
                    $parameterReplacementMap[$paramName] = $newParamName.TrimStart('$')
                    $variableReplacementMap[$paramName] = $newParamName
                }
            }
        }

        if ($func.Body.ParamBlock) {
            foreach ($param in $func.Body.ParamBlock.Parameters) {
                $paramName = $param.Name.VariablePath.UserPath
                if (-not $parameterReplacementMap.ContainsKey($paramName)) {
                    $newParamName = ObfuscateVariables $paramName $true
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

    # add function definitions with improved handling
    foreach ($func in $functionDefinitions) {
        if ($func.Name -in $functionNamesIgnore) { continue }

        $functionKeyword = "function "
        $fullStartOffset = $func.Extent.StartOffset
        $nameStartOffset = $func.Extent.StartOffset

        # find actual start of function name by checking for the keyword
        if ($func.Extent.Text.TrimStart().StartsWith($functionKeyword)) {
            $nameStartOffset = $fullStartOffset + $func.Extent.Text.IndexOf($functionKeyword) + $functionKeyword.Length
        }

        $allReplacements += @{
            StartOffset = $nameStartOffset
            Length = $func.Name.Length
            OriginalName = $func.Name
            Text = $func.Name
            Type = "Function"
            RequiresKeyword = $true  # new flag to indicate this needs special handling
            FullStartOffset = $fullStartOffset
        }
    }

    # add function calls and parameters with improved validation
    foreach ($call in $allCommandCalls) {
        $commandName = $call.CommandElements[0].Extent.Text

        if ($commandName -in $functionNamesIgnore) { continue }

        if ($functionReplacementMap.ContainsKey($commandName)) {
            # verify the replacement exists and is valid
            $newName = $functionReplacementMap[$commandName]
            $allReplacements += @{
                StartOffset = $call.CommandElements[0].Extent.StartOffset
                Length = $commandName.Length
                OriginalName = $commandName
                Text = $commandName
                Type = "Function"
                RequiresKeyword = $false  # function calls don't need the keyword
            }

            # process parameters
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
    $ArithmeticAsts = $newAst.FindAll({ $args[0] -is [System.Management.Automation.Language.BinaryExpressionAst] -and @("Plus", "Subtract", "Band", "Bxor", "Bor") -contains $args[0].Operator }, $true)
    Write-Host "Found $($barewordAsts.Count) barewords and $($ArithmeticAsts.Count) arithmetic operations"
    $numberAsts = $newAst.FindAll({ $args[0] -is [System.Management.Automation.Language.ConstantExpressionAst] -and $args[0].StaticType.Name -eq "Int32" }, $true)

    $barewordReplacements = @()
    $numberReplacements = @()

    foreach ($bareword in $barewordAsts) {
        if ($functionReplacementMap.ContainsKey($bareword.Extent.Text)) { continue }

        # check parent to see if this is a command
        $isCommandFirst = $false
        if ($bareword.Parent -is [System.Management.Automation.Language.CommandAst]) {
            # check if its the first bareword (the actual command)
            $commandElements = $bareword.Parent.CommandElements
            $isCommandFirst = $commandElements[0].Extent.Text -eq $bareword.Extent.Text

            # if not then skip
            if (-not $isCommandFirst) {
                continue
            }
        }

        # get command type information
        $commandInfo = Get-CommandType -CommandName $bareword.Extent.Text

        # generate a new random replacement for each instance
        # pass the command info to ObfuscateCommandTypes
        $newBarewordName = ObfuscateCommandTypes -CommandText $bareword.Extent.Text -CommandInfo $commandInfo -RealBearWord $isCommandFirst

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

    # too many numbers lol
    if ($global:pass_number -lt 2) {
        foreach ($number in $numberAsts) {
            $numberText = $number.Extent.Text
            if ($numberReplacementMap.ContainsKey($numberText)) { continue }

            $newNumber = ObfuscateNumbers $numberText
            $numberReplacements += @{
                StartOffset = $number.Extent.StartOffset
                Length = $number.Extent.Text.Length
                OriginalName = $numberText
                Text = $numberText
                NewName = $newNumber
                Type = "Number"
            }
        }
    }


    $allReplacements = @()

    foreach ($replacement in $barewordReplacements) {
        $allReplacements += $replacement
    }

    foreach ($replacement in $numberReplacements) {
        $allReplacements += $replacement
    }

    $allReplacements = $allReplacements | Sort-Object { $_.StartOffset } -Descending


    foreach ($replacement in $allReplacements) {
        $newName = switch ($replacement.Type) {
            "Bareword" { $replacement.NewName }
            "Number" { $replacement.NewName }
        }

        Write-Host "Second Pass - Replacing '$($replacement.Text)' at position $($replacement.StartOffset) with '$newName' (Type: $($replacement.Type))"

        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $newName
    }

    $newAst_pass3 = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)
    $AssignmentExpressionAst = $newAst_pass3.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    $assignment_expressions = @()

    foreach ($assignment in $AssignmentExpressionAst) {
        $text = $assignment.Extent.Text

        $obfuscated = WrapObfuscate $text

        $assignment_expressions += @{
            StartOffset = $assignment.Extent.StartOffset
            Length = $assignment.Extent.Text.Length
            OriginalName = $text
            Text = $text
            NewName = $obfuscated
            Type = "Assignment"
        }
    }

    $assignment_expressions = $assignment_expressions | Sort-Object { $_.StartOffset } -Descending

    foreach ($replacement in $assignment_expressions) {
        $newName = switch ($replacement.Type) {
            "Assignment" { $replacement.NewName }
        }

        Write-Host "Third Pass - Replacing '$($replacement.Text)' at position $($replacement.StartOffset) with '$newName' (Type: $($replacement.Type))"

        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $newName
    }


    $newAst_pass4 = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)
    $AssignmentStatmentAst = $newAst_pass4.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)

    $assignment_statements = @()

    foreach ($assignment in $AssignmentStatmentAst) {
        $text = $assignment.Extent.Text

        $obfuscated = WrapObfuscate $text

        $assignment_statements += @{
            StartOffset = $assignment.Extent.StartOffset
            Length = $assignment.Extent.Text.Length
            OriginalName = $text
            Text = $text
            NewName = $obfuscated
            Type = "Assignment"
        }
    }

    $assignment_statements = $assignment_statements | Sort-Object { $_.StartOffset } -Descending

    foreach ($replacement in $assignment_statements) {
        $newName = switch ($replacement.Type) {
            "Assignment" { $replacement.NewName }
        }

        Write-Host "Fourth Pass - Replacing '$($replacement.Text)' at position $($replacement.StartOffset) with '$newName' (Type: $($replacement.Type))"

        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $newName
    }

    $newAst_pass5 = [System.Management.Automation.Language.Parser]::ParseInput($code_copy, [ref]$null, [ref]$null)
    $binaryExpressionAst = $newAst_pass5.FindAll({ $args[0] -is [System.Management.Automation.Language.BinaryExpressionAst] -and @("Plus", "Subtract", "Band", "Bxor", "Bor") -contains $args[0].Operator }, $true)

    #get the binary expressions that only have 2 ConstantExpressionAst children
    $binary_expressions = @()

    foreach ($binary in $binaryExpressionAst) {
        $left = $binary.Left
        $right = $binary.Right

        if ($left -is [System.Management.Automation.Language.ConstantExpressionAst] -and $right -is [System.Management.Automation.Language.ConstantExpressionAst]) {
            $text = $binary.Extent.Text

            $obfuscated = ApplyMBAObfuscation $left.Extent.Text $right.Extent.Text $binary.Operator $mba_depth

            $binary_expressions += @{
                StartOffset = $binary.Extent.StartOffset
                Length = $binary.Extent.Text.Length
                OriginalName = $text
                Text = $text
                NewName = $obfuscated
                Type = "Binary"
            }
        }
    }

    $binary_expressions = $binary_expressions | Sort-Object { $_.StartOffset } -Descending

    foreach ($replacement in $binary_expressions) {
        $newName = switch ($replacement.Type) {
            "Binary" { $replacement.NewName }
        }

        Write-Host "Fifth Pass - Replacing '$($replacement.Text)' at position $($replacement.StartOffset) with '$newName' (Type: $($replacement.Type))"

        $code_copy = Replace-TextAtPosition -SourceText $code_copy `
                                        -StartPosition $replacement.StartOffset `
                                        -Length $replacement.Length `
                                        -ReplacementText $newName
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
    } catch {
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

    # cache the result for future calls
    $CommandTypeCache[$CommandName] = $result
    return $result
}

function Main($payload) {
    $obfuscatedCode = ObfuscateCode $payload
    if ($times_wrap -ne 0) {
        $totalSteps = ($times_wrap * 2) + 1
        $currentStep = 0
        while ($times_wrap -ne 0) {
            $global:pass_number++
            $times_wrap = $times_wrap - 1
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

function Get-FileLocation {
    while ($true) {
        $file_location = Read-Host "Enter the file location -> "
        if ((Test-Path $file_location) -and $file_location -like "*.ps1") {
            return $file_location
        } else {
            Write-Host "File not found or not a .ps1 file: $file_location"
        }
    }
}

#see if file was passed in through command line
if ($args.Count -eq 1) {
    $location_good = $args[0]
} else {
    $location_good = Get-FileLocation
}

$stuff = Get-Content $location_good -Raw

$obfuscatedCode = Main $stuff

$out_file = $location_good -replace ".ps1", "_obf.ps1"
$obfuscatedCode | Out-File $out_file -Force