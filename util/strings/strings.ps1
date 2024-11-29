#TODO add env var obf
$split_string_verbose = $false

function ObfuscateString($string, $string_type) {
    $splitting = $true
    if ($string.Length -lt 4) {
        $splitting = $false
    }
    if ($string.StartsWith("'") -and $string.EndsWith("'")) {
        $string = $string.Substring(1, $string.Length - 2)
    }
    if ($string.StartsWith('"') -and $string.EndsWith('"')) {
        $string = $string.Substring(1, $string.Length - 2)
    }
    $string = $string -replace "`'", "`'`'"
    if ($string -eq "") {
        return "''"
    }

    # if there is a backtick in the string and the string is double quoted, we need to just return the string

    if ($string.Contains("``") -and $string_type -eq "DoubleQuoted") {
        return '"' + $string + '"'
    }

    $out_content = ""

    if ($splitting -eq $false) {
        $string_pieces = @($string)
    } else {
        try {
            [string[]]$string_pieces = SplitStrings $string
        }
        catch {
            Write-Host "Error splitting string: $string"
            Read-Host "Press enter to exit..."
            exit 1
        }
    }

    for ($i = 0; $i -lt $string_pieces.Count; $i++) {
        $small_string = $string_pieces[$i]
        $obfuscationFunctions = @(
            #"ObfuscateStringReverse",
            "ObfuscateBase64String",
            #"ObfuscateReplaceString",
            "ObfuscateHexString",
            "ObfuscateByteArrayString",
            "ObfuscateMixedString"
        )
        $random = Get-Random -Minimum 0 -Maximum $obfuscationFunctions.Length
        $obfuscationFunction = $obfuscationFunctions[$random]
        $out_content2 = & $obfuscationFunction $small_string
        
        if ($i -lt ($string_pieces.Count - 1)) {
            $out_content += "$out_content2 + "
        } else {
            $out_content += $out_content2
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

function ObfuscateByteArrayString($string) {
    #WORKING
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
    $good_bytes = "(" + ($bytes -join ', ') + ")"
    $command = "[System.Text.Encoding]::UTF8.GetString($good_bytes)"
    return $command
}

function ObfuscateHexString($string) {
    if ([string]::IsNullOrEmpty($string)) {
        return "''"
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
    $hexString = $bytes | ForEach-Object { "0x{0:x2}" -f $_ }
    $hexString = "($($hexString -join ', '))"
    $command = "[System.Text.Encoding]::UTF8.GetString($hexString)"
    return $command
}

function ObfuscateMixedString($string) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
    $hexArray = $bytes | ForEach-Object { "0x{0:x2}" -f $_ }

    if ($bytes.Length -eq 1) {
        $byteArrayString = $bytes[0]
    } else {
        $mixedArray = for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) {
                $bytes[$i]
            } else {
                $hexArray[$i]
            }
        }
        $byteArrayString = "(" + ($mixedArray -join ', ') + ")"
    }

    $command = "[System.Text.Encoding]::UTF8.GetString($byteArrayString)"
    return $command
}

function SplitStrings {
    param (
        [string]$string
    )

    $string_length = $string.Length
    if ($string_length -lt 2) {
        return @($string)
    }

    # array to store chunks
    $result = @()
    $i = 0

    while ($i -lt $string_length) {
        if ($string_length -lt 10) {
            $chunk_length = Get-Random -Minimum 2 -Maximum 5
        } elseif ($string_length -lt 50) {
            $chunk_length = Get-Random -Minimum 15 -Maximum 25
        } elseif ($string_length -lt 100) {
            $chunk_length = Get-Random -Minimum 24 -Maximum 50
        } elseif ($string_length -lt 200) {
            $chunk_length = Get-Random -Minimum 50 -Maximum 100
        } elseif ($string_length -lt 500) {
            $chunk_length = Get-Random -Minimum 75 -Maximum 200
        } elseif ($string_length -lt 1000) {
            $chunk_length = Get-Random -Minimum 100 -Maximum 300
        } else {
            $chunk_length = Get-Random -Minimum 200 -Maximum 500
        }

        # make sure we got the remaining string length
        $length = [Math]::Min($chunk_length, $string_length - $i)

        # add it to the chunk array
        $result += $string.Substring($i, $length)
        
        # move the index forward of how far we've gone.
        $i += $length

        if ($split_string_verbose) {
            Write-Host "Chunk: $($result[-1])"
        }
    }

    #pretty print the chunks
    if ($split_string_verbose) {
        Write-Host "Chunks: $($result -join ', ')"
    }

    return $result
}

function ObfuscateReplaceString($string) {
    #BROKEN
    $split_str = SplitStrings $string
    $replaces_amount = $split_str.Length

    $set_dict = @{}

    for ($i = 0; $i -lt $replaces_amount; $i++) {
        $set_dict[$i] = $split_str[$i]
    }

    $shuffled_key_locations = @()
    for ($i = 0; $i -lt $replaces_amount; $i++) {
        $shuffled_key_locations += $i
    }

    #this is the order we will put the keys in the string.
    $shuffled_keys = $shuffled_key_locations | Sort-Object {Get-Random}

    $format_string = ""
    $arguments = @()

    #make the output look like "{1}{0}{2}" -f "b", "a", "c"
    for ($i = 0; $i -lt $shuffled_keys.Length; $i++) {
        $format_string += "{$($shuffled_keys[$i])}"
        $arguments += $set_dict[$i]
    }

    $format_string = '"' + $format_string + '"'
    $arguments = '"' + ($arguments -join '", "') + '"'

    $command = "($format_string -f $arguments)"

    Write-Host "Obfuscated: $command"
    Write-Host $shuffled_key_locations
    Write-Host $shuffled_keys
    Write-Host $format_string
    Write-Host $arguments

    return $command
}

function make_random_string($length) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

## Test the obfuscation
#for ($i = 0; $i -lt 1000; $i++) {
#    $length = Get-Random -Minimum 1 -Maximum 10
#    $string = make_random_string $length
#    $obfuscated_string = ObfuscateReplaceString $string
#    $deobfuscated_string = Invoke-Expression $obfuscated_string
#    
#    if ($string -ne $deobfuscated_string) {
#        Write-Host "-------------------------------------"
#        Write-Host "$string"
#        Write-Host "$deobfuscated_string"
#        Write-Host "Failed to deobfuscate string: $string"
#        Write-Host "Obfuscated: $obfuscated_string"
#        Write-Host "Deobfuscated: $deobfuscated_string"
#        Write-Host "Press Enter to continue..."
#        Read-Host
#    }
#}