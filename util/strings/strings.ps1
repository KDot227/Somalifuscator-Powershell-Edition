#TODO add env var obf

function ObfuscateString($string) {
    #make a list of all the functions that can obfuscate $string then pick a random one and pass in string and return the output
    #remove first and last character
    $string = $string.Substring(1, $string.Length - 2)
    $string = $string -replace "`'", "`'`'"
    $out_content = ""
    $string_pieces = SplitStrings $string
    foreach ($small_string in $string_pieces) {
        $obfuscationFunctions = @(
            #"ObfuscateStringReverse"
            "ObfuscateBase64String"
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
    $split_ammount = Get-Random -Minimum 2 -Maximum $string_length
    $split_string = $string -split "(?<=\G.{$split_ammount})"
    return $split_string
}