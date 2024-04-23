$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function ObfuscateFunctionNames($name) {
    return Create_Random_String
}

function Create_Random_String() {
    $string = "KDOT!?!_"
    for ($i = 0; $i -lt 10; $i++) {
        $string += $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)]
    }
    return $string
}