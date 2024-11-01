#TODO add env var obf

function ObfuscateString($string) {
    #make a list of all the functions that can obfuscate $string then pick a random one and pass in string and return the output
    #remove first and last character
    $string = $string.Substring(1, $string.Length - 2)
    $string = $string -replace "`'", "`'`'"
    if ($string -eq "") {
        return "''"
    }
    $out_content = ""
    try {
        $string_pieces = SplitStrings $string
    }
    catch {
        Write-Host "Error splitting string: $string"
        Read-Host "Press enter to exit..."
        exit 1
    }
    
    foreach ($small_string in $string_pieces) {
        $obfuscationFunctions = @(
            #"ObfuscateStringReverse",
            "ObfuscateBase64String"
            #"ObfuscateReplaceString"
        )
        $random = Get-Random -Minimum 0 -Maximum $obfuscationFunctions.Length
        $obfuscationFunction = $obfuscationFunctions[$random]
        $out_content2 = & $obfuscationFunction $small_string
        #check to see if this is the last iteration
        if ($small_string -eq $string_pieces[-1]) {
            $out_content += "$out_content2"
        }
        else {
            $out_content += "$out_content2 + "
        }
    }

    return "($out_content)"
}

function ObfuscateStringReverse($string) {
    #WORKING
    $split_string = $string -split ""
    [array]::Reverse($split_string)
    $reversed_string = $split_string -join ''
    $command = "('$reversed_string'[-1..-$($reversed_string.Length)] -join '')"
    return $command
}

function ObfuscateBase64String($string) {
    #WORKING
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
    $encoded = [System.Convert]::ToBase64String($bytes)
    $command = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('$encoded'))"
    return $command
}

function SplitStrings($string) {
    #WORKING
    #split the string into an array of multiple substrings of the $string variable
    $string_length = $string.Length
    if ($string_length -lt 2) {
        return $string
    }
    $split_ammount = Get-Random -Minimum 2 -Maximum $string_length
    $split_string = $string -split "(?<=\G.{$split_ammount})"
    return $split_string
}

function ObfuscateReplaceString($string) {
    $split_str = SplitStrings $string
    $replaces_amount = $split_str.Length

    $set_dict = @{}

    for ($i = 0; $i -lt $replaces_amount; $i++) {
        $set_dict[$i] = $split_str[$i]
    }

    $shuffled_keys = ($set_dict.Keys | Get-Random -Count $set_dict.Count)

    $format_string = ""
    $arguments = @()

    foreach ($key in $shuffled_keys) {
        $format_string += "{$key}"
        $arguments += "`"$($set_dict[$key])`""
    }

    $out_command = "`"{0}`" -f {1}" -f $format_string, ($arguments -join ', ')

    return $out_command
}

#ObfuscateReplaceString "Write-Host testcuz"
