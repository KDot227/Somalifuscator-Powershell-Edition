function ObfuscateVariables($variable) {
    return MakeRandomVariableName 10
}

function MakeRandomVariableName($length) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $name = "`$kdot"
    for ($i = 0; $i -lt $length; $i++) {
        $name += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
    }
    return $name
}