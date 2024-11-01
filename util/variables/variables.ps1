$bad_vars2 = @('$_', '$ignore', '$PSScriptRoot', '$global', '$MyInvocation', '$local', '`$', '$args', '$ErrorActionPreference', '$ProgressPreference', '$PROFILE')

function ObfuscateVariables($variable_good) {
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
    return MakeRandomVariableName 10
}

function MakeRandomVariableName($length) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $name = "`$KDOT"
    for ($i = 0; $i -lt $length; $i++) {
        $name += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
    }
    return $name
}

function ObfuscateTrue {
    return '$true'
}

function ObfuscateFalse {
    return '$false'
}

function ObfuscateNull {
    return '$null'
}