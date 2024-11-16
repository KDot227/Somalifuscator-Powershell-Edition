#. "$scriptPath\util\strings\strings.ps1"
#. "$scriptPath\util\commands\commands.ps1"

function WrapObfuscate($code) {
    $obfuscated_string = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($code))
    $base64 = ObfuscateString $obfuscated_string
    $iex_obf = DotObfuscateBareWord "Invoke-Expression"
    return "$iex_obf([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64)))"
}