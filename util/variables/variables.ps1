$bad_vars2 = @('$_', '$ignore', '$PSScriptRoot', '$global', '$MyInvocation', '$local', '`$', '$args', '$ErrorActionPreference', '$ProgressPreference', '$PROFILE')
$good_chars = "cdghijklmopqsuwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function ObfuscateVariables($variable_good, $parameter) {
    $lower_var = $variable_good.ToLower()
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

function RandomChangeVar($variable, $parameter) {
    # if the variable is in good_chars, do random capitalization and randomly add a ` in front.
    $ticks = Get-Random -Minimum 0 -Maximum 2
    if ($parameter -eq $true) {
        $ticks = 999
    }
    $variable = $variable -split ""
    for ($i = 0; $i -lt $variable.Length; $i++) {
        if ($i -gt 0 -and $variable[$i - 1] -eq '`' -and $good_chars.Contains($variable[$i])) {
            continue
        }

        if ($good_chars.Contains($variable[$i]) -and ($variable[$i] -ne "")) {
            $random = Get-Random -Minimum 0 -Maximum 2
            $random2 = Get-Random -Minimum 0 -Maximum 2
            if ($random -eq 0) {
                $variable[$i] = $variable[$i].ToUpper()
            } else {
                $variable[$i] = $variable[$i].ToLower()
            }

            if (($random2 -eq 0) -and ($ticks -eq 0)) {
                $variable[$i] = "``" + $variable[$i]
            }
        }
    }
    $variable = $variable -join ''
    if ($ticks -eq 0) {
        #insert a { at the beginning after the first character and a } at the end
        $variable = $variable.Insert(1, "{")
        $variable += "}"
    }
    return $variable
}

function ObfuscateTrue {
    #ideas from https://github.com/t3l3machus/PowerShell-Obfuscation-Bible?tab=readme-ov-file#obfuscate-boolean-values
    $choices = @(
        '[bool][bool]',
        '[bool][char]',
        '[bool][int] ',
        '[bool][string]',
        '[bool][double]',
        '[bool][short]',
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