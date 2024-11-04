$printables = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
$banned = "abefnrtvABEFNRTV"

function ObfuscateCommandTypes {
    param(
        [string]$CommandText,
        [hashtable]$CommandInfo
    )
    if ($CommandInfo.IsBuiltIn) {
        switch ($CommandInfo.Type) {
            "Cmdlet" {
                $verb, $noun = $CommandText -split '-'
                if ($noun) {
                    if ($verbose) {
                        Write-Host $CommandText NOUN
                    }
                    return ObfuscateMethodsGood $CommandText
                }
                if ($verbose) {
                    Write-Host $CommandText VERB
                }
                return ObfuscateMethodsGood $CommandText
            }
            "Function" {
                if ($verbose) {
                    Write-Host $CommandText FUNCTION
                }
                return RandomUpercaseCharacters $CommandText
            }
            "Alias" {
                return RandomUpercaseCharacters $CommandText
            }
            default {
                return RandomUpercaseCharacters $CommandText
            }
        }
    }
    else {
        if ($verbose) {
            Write-Host $CommandText CUSTOM
        }
        return RandomUpercaseCharacters $CommandText
    }
}

function Get-RandomString {
    $length = Get-Random -Minimum 8 -Maximum 16
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function RandomUpercaseCharacters($string) {
    $string = $string -split ""
    $string = $string | ForEach-Object {
        if ($printables.Contains($_) -and ($_ -ne "")) {
            $random = Get-Random -Minimum 0 -Maximum 2
            if ($random -eq 0) {
                $_.ToUpper()
            }
            else {
                $_.ToLower()
            }
        }
        else {
            $_
        }
    }
    return $string -join ''
}

function ObfuscateMethodCalls($string, $quotes = $true) {
    $out_str = ""
    $quotes_random = Get-Random -Minimum 0 -Maximum 2
    if ($quotes -eq $false) {
        $quotes_random = 1
    }
    $string = $string -split ""
    $string | ForEach-Object {
        if ($printables.Contains($_) -and ($_ -ne "") -and (!($banned.Contains($_)))) {
            $random = Get-Random -Minimum 0 -Maximum 2
            if ($random -eq 0) {
                $out_str += '`' + $_
            }
            else {
                $out_str += $_
            }
        }
        else {
            $out_str += $_
        }
    }
    if ($quotes_random -eq 0) {
        $out_str = "`"$out_str`""
    }
    return $out_str
}

function ObfuscateMethodsGood($string) {
    $last = $false
    $first = $true
    $out_str = ""
    if ($string.Contains("KDOT!?!_")) {
        return $string
    }
    $string = $string -split ""
    $string | ForEach-Object {
        if (($first -eq $true) -and ($_ -ne "")) {
            $out_str += $_
            $first = $false
        }
        else {
            if ($_ -ne "") {
                $random = Get-Random -Minimum 0 -Maximum 3
                if (($random -eq 0) -and ($last -eq $false)) {
                    $out_str += "`'$_`'"
                    $last = $true
                }
                elseif (($random -eq 1) -and ($last -eq $false) -and ($printables.Contains($_)) -and ($_ -ne "") -and (!($banned.Contains($_)))) {
                    $out_str += "``$_"
                    $last = $true
                }
                else {
                    $out_str += $_
                    $last = $false
                }
            }
        }
    }
    return $out_str
}

#ObfuscateMethodsGood "KDOT_frslwSZslJ"