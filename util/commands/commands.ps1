$printables = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
$banned = "abefnrtvABEFNRTV"

function ObfuscateCommandTypes {
    param(
        [string]$CommandText,
        [hashtable]$CommandInfo,
        [bool]$RealBearWord = $false
    )

    if ($RealBearWord) {
        return DotObfuscateBareWord $CommandText
    }

    if ($CommandInfo.IsBuiltIn) {
        switch ($CommandInfo.Type) {
            "Cmdlet" {
                $verb, $noun = $CommandText -split '-'
                if ($noun) {
                    if ($verbose) {
                        Write-Host $CommandText NOUN
                    }
                    return DotObfuscateBareWord $CommandText
                }
                if ($verbose) {
                    Write-Host $CommandText VERB
                }
                return DotObfuscateBareWord $CommandText
            }
            "BuiltinAlias" {
                return DotObfuscateBareWord $CommandText
            }
            "Function" {
                if ($verbose) {
                    Write-Host $CommandText FUNCTION
                }
                return DotObfuscateBareWord $CommandText
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
    for ($i = 0; $i -lt $string.Length; $i++) {
        if ($i -gt 0 -and $string[$i - 1] -eq '`' -and $printables.Contains($string[$i])) {
            continue
        }

        if ($printables.Contains($string[$i]) -and ($string[$i] -ne "")) {
            $random = Get-Random -Minimum 0 -Maximum 2
            if ($random -eq 0) {
                $string[$i] = $string[$i].ToUpper()
            }
            else {
                $string[$i] = $string[$i].ToLower()
            }
        }
    }
    return $string -join ''
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

function DotObfuscateBareWord($string) {
    $split_str = $string -split ""
    $map = @()
    # get the char value for each char in the string
    $split_str | ForEach-Object {
        if ($_ -ne "") {
            $map += [int][char]$_
        }
    }

    $out_str = ".("

    $map | ForEach-Object {
        if ($global:pass_number -lt 2) {
            $obfuscated = AddOrSubtractRandomEQ $_
            $out_str += "[char]($obfuscated)+"
        } else {
            $out_str += "[char]($_)+"
        }

    }
    $out_str = $out_str.Substring(0, $out_str.Length - 1)
    $out_str += ")"
    return $out_str
}

function AddOrSubtractRandomEQ($number_to_obf) {
    #get 3 random numbers
    $number1 = Get-Random -Minimum 1 -Maximum 10000
    $number2 = Get-Random -Minimum 1 -Maximum 10000
    $number3 = Get-Random -Minimum 1 -Maximum 10000

    $signs = @('+', '-')

    $num1_sign = Get-Random -Minimum 0 -Maximum 2
    $num2_sign = Get-Random -Minimum 0 -Maximum 2
    $num3_sign = Get-Random -Minimum 0 -Maximum 2

    $sign1 = $signs[$num1_sign]
    $sign2 = $signs[$num2_sign]
    $sign3 = $signs[$num3_sign]

    $opposite_sign1 = $signs[1 - $num1_sign]
    $opposite_sign2 = $signs[1 - $num2_sign]
    $opposite_sign3 = $signs[1 - $num3_sign]

    $final_number = "$number_to_obf $sign1 $number1 $sign2 $number2 $sign3 $number3"
    $out_final = Invoke-Expression $final_number

    $new_problem = "$out_final $opposite_sign1 $number1 $opposite_sign2 $number2 $opposite_sign3 $number3"
    return "($new_problem)"
}

#ObfuscateMethodsGood "KDOT_frslwSZslJ"