$bad_vars2 = @('$_', '$ignore', '$PSScriptRoot', '$global', '$MyInvocation', '$local', '`$', '$args', '$ErrorActionPreference', '$ProgressPreference', '$PROFILE', '$PID')
$good_chars = "bcdghijklmopqsuwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function ObfuscateVariables($variable_good, $parameter) {
    $lower_var = $variable_good.ToLower()
    if ($lower_var.StartsWith('$kdot_')) {
        return $variable_good
    }

    switch ($lower_var) {
        '$true' { return ObfuscateTrue }
        '$false' { return ObfuscateFalse }
        '$null' { return ObfuscateNull }
    }

    foreach ($bad_var in $bad_vars2) {
        if ($lower_var -contains $bad_var) {
            return $variable_good
        }
    }

    $var = MakeRandomVariableName 10
    $new_var_final = RandomChangeVar $var $parameter
    Write-Host "Obfuscating variable: $variable_good to $new_var_final"
    return $new_var_final
}

function MakeRandomVariableName($length) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $name = "`$KDOT"
    for ($i = 0; $i -lt $length; $i++) {
        $name += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
    }
    return $name
}

function RandomCapitalization($string) {
    $string = $string -split ""
    for ($i = 0; $i -lt $string.Length; $i++) {
        $random = Get-Random -Minimum 0 -Maximum 2
        if ($random -eq 0) {
            $string[$i] = $string[$i].ToUpper()
        } else {
            $string[$i] = $string[$i].ToLower()
        }
    }
    $string = $string -join ''
    return $string
}

function RandomChangeVar($variable, $parameter) {
    $ticks = Get-Random -Minimum 0 -Maximum 5
    if ($parameter -eq $true) {
        $ticks = 999
    }
    $variable = $variable -split ""
    for ($i = 0; $i -lt $variable.Length; $i++) {
        if ($i -gt 0 -and $variable[$i - 1] -eq '`' -and $good_chars.Contains($variable[$i])) {
            continue
        }

        if ($good_chars.Contains($variable[$i]) -and ($variable[$i] -ne "")) {
            $variable[$i] = RandomCapitalization($variable[$i])

            if ($variable[$i] -cmatch '[A-Z]' -and (Get-Random -Minimum 0 -Maximum 2) -eq 0 -and ($ticks -lt 4)) {
                $variable[$i] = "``" + $variable[$i]
            }
        }
    }
    $variable = $variable -join ''
    if ($ticks -lt 4) {
        $variable = $variable.Insert(1, "{")
        $variable += "}"
    }
    return $variable
}

function ReObfuscateVariable($variable) {
    $has_ticks = $variable -match "``"
    if ($has_ticks) {
        $variable = $variable.Substring(2, $variable.Length - 3)
        $variable = $variable.Replace("``", "")
        $ticks = Get-Random -Minimum 0 -Maximum 5
        $variable = $variable -split ""
        for ($i = 0; $i -lt $variable.Length; $i++) {
            if ($good_chars.Contains($variable[$i]) -and ($variable[$i] -ne "")) {
                $variable[$i] = RandomCapitalization($variable[$i])
                if ($variable[$i] -cmatch '[A-Z]' -and (Get-Random -Minimum 0 -Maximum 2) -eq 0 -and ($ticks -lt 4)) {
                    $variable[$i] = "``" + $variable[$i]
                }
            }
        }
        $variable = $variable -join ''
        $to_return = "`${" + $variable + "}"
        return $to_return
    } else {
        $variable = $variable -split ""
        for ($i = 0; $i -lt $variable.Length; $i++) {
            if ($good_chars.Contains($variable[$i]) -and ($variable[$i] -ne "")) {
                $variable[$i] = RandomCapitalization($variable[$i])
            }
        }
        $variable = $variable -join ''
        return $variable
    }
}


function ObfuscateTrue {
    #ideas from https://github.com/t3l3machus/PowerShell-Obfuscation-Bible?tab=readme-ov-file#obfuscate-boolean-values
    $choices = @(
        '[bool][bool]',
        '[bool][char]',
        '[bool][int] ',
        '[bool][string]',
        '[bool][double]',
        '[bool][decimal]',
        '[bool][byte]',
        '[bool][timespan]',
        '[bool][datetime]',
        '(9999 -eq 9999)',
        '([math]::Round([math]::PI) -eq (4583 - 4580))',
        '[Math]::E -ne [Math]::PI',
        '[bool](![bool]$null)',
        '!!!![bool][bool][bool][bool][bool][bool]',
        '![bool]$null',
        '![bool]$False',
        '[bool][System.Collections.ArrayList]',
        '[bool][System.Collections.CaseInsensitiveComparer]',
        '[bool][System.Collections.Hashtable]'
    )

    $choice = Get-Random -Minimum 0 -Maximum $choices.Length
    $final = $choices[$choice]
    return "($final)"
}

function ObfuscateFalse {
    return '$false'
}

function ObfuscateNull {
    return '$null'
}

#ObfuscateVariables '$this_is_a_test'