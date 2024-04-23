$printables = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
$banned = "abefnrtv"

function ObfuscateCommandTypes($command) {
    return RandomUpercaseCharacters $command
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
                $_
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