# Define characters for function name generation
$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function Create_Random_String {
    $string = $characters[(Get-Random -Minimum 26 -Maximum $characters.Length)]

    for ($i = 0; $i -lt 15; $i++) {
        $string += $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)]
    }
    return $string
}

function ObfuscateFunctionNames($name) {
    $newName = Create_Random_String
    return $newName
}