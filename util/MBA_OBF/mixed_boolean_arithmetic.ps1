$dict_operation_rules = @{
    Bxor = "(LEFT -Bor RIGHT) - (LEFT -Band RIGHT)"
    Plus = "(LEFT -Band RIGHT) + (LEFT -Bor RIGHT)"
    Subtract = "(LEFT -Bxor -RIGHT) + 2*(LEFT -Band -RIGHT)"
    Band = "(LEFT + RIGHT) - (LEFT -Bor RIGHT)"
    Bor = "LEFT + RIGHT + 1 + (-bnot LEFT -Bor -bnot RIGHT)"
}

function ApplyMBAObfuscation {
    param(
        [string] $left,
        [string] $right,
        [string] $operator,
        [int] $depth = 1
    )

    $operation = switch ($operator) {
        "Bxor" { $dict_operation_rules.Bxor }
        "Plus" { $dict_operation_rules.Plus }
        "Subtract" { $dict_operation_rules.Subtract }
        "Band" { $dict_operation_rules.Band }
        "Bor" { $dict_operation_rules.Bor }
        default { Write-Host "Invalid Operation"; return $null }
    }

    $operation = $operation.Replace("LEFT", $left).Replace("RIGHT", $right)

    if ($depth -gt 1) {
        $parsedAST = [System.Management.Automation.Language.Parser]::ParseInput($operation, [ref]$null, [ref]$null)
        
        $operations = $parsedAST.FindAll({$args[0] -is [System.Management.Automation.Language.BinaryExpressionAst]}, $true)
        foreach ($op in $operations) {
            $newOp = switch ($op.Operator) {
                "Band" { ApplyMBAObfuscation $op.Left.Extent.Text $op.Right.Extent.Text "Band" ($depth - 1) }
                "Bor" { ApplyMBAObfuscation $op.Left.Extent.Text $op.Right.Extent.Text "Bor" ($depth - 1) }
                "Bxor" { ApplyMBAObfuscation $op.Left.Extent.Text $op.Right.Extent.Text "Bxor" ($depth - 1) }
                "Plus" { ApplyMBAObfuscation $op.Left.Extent.Text $op.Right.Extent.Text "Plus" ($depth - 1) }
                "Subtract" { ApplyMBAObfuscation $op.Left.Extent.Text $op.Right.Extent.Text "Subtract" ($depth - 1) }
                default { $null }
            }
            if ($newOp) {
                $operation = $operation.Replace($op.Extent.Text, "($newOp)")
            }
        }
    }

    return $operation
}

function TestMBAObfuscation {
    $left = 100
    $right = 1000
    $operator = "Subtract"
    $depth = 2
    $result = ApplyMBAObfuscation $left $right $operator $depth
    Write-Host $result
}

#TestMBAObfuscation
