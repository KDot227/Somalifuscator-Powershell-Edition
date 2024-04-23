$compressionTypes = 'Gzip', 'Deflate', 'ZLib'
$method = ""
$decode_command = @"
function Decode-Code(`$compressedBytes, `$compressionPick) {
    [System.IO.MemoryStream] `$input1 = New-Object System.IO.MemoryStream
    `$input1.Write(`$compressedBytes, 0, `$compressedBytes.Length)
    `$input1.Seek(0, [IO.SeekOrigin]::Begin)

    `$compressionStream = $null
    `$reader = $null
    `$decompressedData = $null

    if (`$compressionPick -eq 'Gzip') {
        `$compressionStream = New-Object System.IO.Compression.GzipStream `$input1, ([IO.Compression.CompressionMode]::Decompress)
    } elseif (`$compressionPick -eq 'Deflate') {
        `$compressionStream = New-Object System.IO.Compression.DeflateStream `$input1, ([IO.Compression.CompressionMode]::Decompress)
    } elseif (`$compressionPick -eq 'ZLib') {
        `$compressionStream = New-Object System.IO.Compression.ZLibStream `$input1, ([IO.Compression.CompressionMode]::Decompress)
    }

    `$reader = New-Object System.IO.StreamReader `$compressionStream
    `$decompressedData = `$reader.ReadToEnd()

    `$reader.Close()
    `$compressionStream.Close()

    `$input1.Close()
    return `$decompressedData
}
"@

function Read-And-Interpret-Script($scriptPath) {
    $scriptContent = [System.IO.File]::ReadAllBytes($scriptPath)
    
    # Generate a random compression type each time
    $compressionPick = $compressionTypes | Get-Random
    
    $encodedScriptContent = Encode-Code -code $scriptContent -compressionPick $compressionPick
    Write-Host "Encoded Script Content:"
    Write-Host $encodedScriptContent

    $decodedScriptContent = Decode-Code -compressedBytes $encodedScriptContent -compressionPick $compressionPick
    
    # Print the decoded script content turned back into text
    Write-Host "Decoded Script Content:"
    Write-Host $decodedScriptContent[1]
}

function Obfuscate-Code($code) {
    $obfuscatedCode = $code
    return $obfuscatedCode
}

function Encode-Code($code, $compressionPick) {
    [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $compressionStream = $null

    if ($compressionPick -eq 'Gzip') {
        $compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    } elseif ($compressionPick -eq 'Deflate') {
        $compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
    } elseif ($compressionPick -eq 'ZLib') {
        $compressionStream = New-Object System.IO.Compression.ZLibStream $output, ([IO.Compression.CompressionMode]::Compress)
    }

    $compressionStream.Write($code, 0, $code.Length)
    $compressionStream.Close()
    $compressedBytes = $output.ToArray()

    $output.Close()
    return $compressedBytes
}

function Decode-Code($compressedBytes, $compressionPick) {
    [System.IO.MemoryStream] $input1 = New-Object System.IO.MemoryStream
    $input1.Write($compressedBytes, 0, $compressedBytes.Length)
    $input1.Seek(0, [IO.SeekOrigin]::Begin)

    $compressionStream = $null
    $reader = $null
    $decompressedData = $null

    if ($compressionPick -eq 'Gzip') {
        $compressionStream = New-Object System.IO.Compression.GzipStream $input1, ([IO.Compression.CompressionMode]::Decompress)
    } elseif ($compressionPick -eq 'Deflate') {
        $compressionStream = New-Object System.IO.Compression.DeflateStream $input1, ([IO.Compression.CompressionMode]::Decompress)
    } elseif ($compressionPick -eq 'ZLib') {
        $compressionStream = New-Object System.IO.Compression.ZLibStream $input1, ([IO.Compression.CompressionMode]::Decompress)
    }

    $reader = New-Object System.IO.StreamReader $compressionStream
    $decompressedData = $reader.ReadToEnd()

    $reader.Close()
    $compressionStream.Close()

    $input1.Close()
    return $decompressedData
}





$scriptPath = "example\test.ps1"
Read-And-Interpret-Script -scriptPath $scriptPath