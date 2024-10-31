$bad_vars2 = @('$_', '$ignore', '$PSScriptRoot', '$global', '$MyInvocation', '$local', '`$', '$args')

function ObfuscateVariables($variable) {
    $lower_var = $variable.ToLower()
    switch ($lower_var) {
        '$true' { return ObfuscateTrue }
        '$false' { return ObfuscateFalse }
        '$null' { return ObfuscateNull }
    }
    
    foreach ($bad_var in $bad_vars2) {
        if ($variable.StartsWith($bad_var)) {
            return $variable
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