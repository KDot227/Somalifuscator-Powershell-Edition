# Define constants at the top
$script:printables = [System.Collections.Generic.HashSet[char]]"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
$script:banned = [System.Collections.Generic.HashSet[char]]"abefnrtvABEFNRTV"

function Get-RandomString {
    $length = Get-Random -Minimum 8 -Maximum 16
    return [System.Web.Security.Membership]::GeneratePassword($length, 0)
}

function ObfuscateCommandTypes {
    param(
        [string]$CommandText,
        [hashtable]$CommandInfo,
        [bool]$RealBearWord = $false
    )

    if ($RealBearWord) { return DotObfuscateBareWord $CommandText }
    
    if (-not $CommandInfo.IsBuiltIn) {
        if ($verbose) { Write-Host $CommandText CUSTOM }
        return RandomUpercaseCharacters $CommandText
    }

    switch ($CommandInfo.Type) {
        { $_ -in 'Cmdlet','BuiltinAlias','Function' } {
            if ($verbose -and $_ -ne 'BuiltinAlias') { 
                Write-Host $CommandText $_
            }
            return DotObfuscateBareWord $CommandText
        }
        default { return RandomUpercaseCharacters $CommandText }
    }
}

function RandomUpercaseCharacters {
    param([string]$string)
    
    $chars = $string.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        if ($i -gt 0 -and $chars[$i - 1] -eq '`' -and $printables.Contains($chars[$i])) {
            continue
        }
        if ($printables.Contains($chars[$i])) {
            $chars[$i] = if ((Get-Random -Maximum 2) -eq 0) { [char]::ToUpper($chars[$i]) } else { [char]::ToLower($chars[$i]) }
        }
    }
    return [string]::new($chars)
}

function ObfuscateMethodsGood {
    param([string]$string)
    
    if ($string.Contains("KDOT!?!_")) { return $string }

    $result = [System.Text.StringBuilder]::new($string.Length * 2)
    $last = $false
    
    for ($i = 0; $i -lt $string.Length; $i++) {
        $char = $string[$i]
        if ($i -eq 0) {
            [void]$result.Append($char)
            continue
        }

        if ($last) {
            $last = $false
            [void]$result.Append($char)
            continue
        }

        $random = Get-Random -Maximum 3
        if ($random -eq 0) {
            [void]$result.Append("'$char'")
            $last = $true
        }
        elseif ($random -eq 1 -and $printables.Contains($char) -and !$banned.Contains($char)) {
            [void]$result.Append("``$char")
            $last = $true
        }
        else {
            [void]$result.Append($char)
            $last = $false
        }
    }
    return $result.ToString()
}


function DotObfuscateBareWord([string]$string) {
    # Use StringBuilder for better string concatenation performance
    $StringBuilder = [System.Text.StringBuilder]::new()
    [void]$StringBuilder.Append(".(")
    
    # Convert string to char array directly instead of splitting
    $chars = $string.ToCharArray()
    
    # Process all characters except the last one
    $lastIndex = $chars.Length - 1
    for ($i = 0; $i -lt $lastIndex; $i++) {
        if ($global:pass_number -lt 2) {
            $obfuscated = AddOrSubtractRandomEQ([int]$chars[$i])
            [void]$StringBuilder.Append("[char]($obfuscated)+")
        } else {
            [void]$StringBuilder.Append("[char]($([int]$chars[$i]))+")
        }
    }
    
    # Process the last character (without adding the '+')
    if ($chars.Length -gt 0) {
        if ($global:pass_number -lt 2) {
            $obfuscated = AddOrSubtractRandomEQ([int]$chars[$lastIndex])
            [void]$StringBuilder.Append("[char]($obfuscated)")
        } else {
            [void]$StringBuilder.Append("[char]($([int]$chars[$lastIndex]))")
        }
    }
    
    [void]$StringBuilder.Append(")")
    return $StringBuilder.ToString()
}

function AddOrSubtractRandomEQ([int]$number_to_obf) {
    # Pre-calculate random values
    $numbers = 1..3 | ForEach-Object { Get-Random -Minimum 1 -Maximum 10000 }
    $signs = @('+', '-')
    $signIndices = 1..3 | ForEach-Object { Get-Random -Minimum 0 -Maximum 2 }
    
    # Create expressions using string format for better performance
    $selectedSigns = $signIndices | ForEach-Object { $signs[$_] }
    $oppositeSigns = $signIndices | ForEach-Object { $signs[1 - $_] }
    
    # Build the expression using string format
    $expression = "{0} {1} {2} {3} {4} {5} {6}" -f $number_to_obf, 
                                                    $selectedSigns[0], 
                                                    $numbers[0], 
                                                    $selectedSigns[1], 
                                                    $numbers[1], 
                                                    $selectedSigns[2], 
                                                    $numbers[2]
    
    $result = Invoke-Expression $expression
    
    # Build the final expression
    $finalExpression = "({0} {1} {2} {3} {4} {5} {6})" -f $result,
                                                            $oppositeSigns[0],
                                                            $numbers[0],
                                                            $oppositeSigns[1],
                                                            $numbers[1],
                                                            $oppositeSigns[2],
                                                            $numbers[2]
    
    return $finalExpression
}