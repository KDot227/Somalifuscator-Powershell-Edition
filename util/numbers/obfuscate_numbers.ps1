function ObfuscateNumbers($number) {

}

function AddOrSubtractRandomEQ($number_to_obf) {
    #get 3 random numbers
    $number1 = Get-Random -Minimum 1 -Maximum 10000000
    $number2 = Get-Random -Minimum 1 -Maximum 10000000
    $number3 = Get-Random -Minimum 1 -Maximum 10000000

    $signs = @('+', '-')

    $num1_sign = Get-Random -Minimum 0 -Maximum 2
    $num2_sign = Get-Random -Minimum 0 -Maximum 2
    $num3_sign = Get-Random -Minimum 0 -Maximum 2

    $sign1 = $signs[$num1_sign]
    $sign2 = $signs[$num2_sign]
    $sign3 = $signs[$num3_sign]

    $opposite_sign1 = $signs[1 - $num1_sign]
    $opposite_sign2 = $signs[1 - $num2_sign]
    $opposite_sign3 = $signs[1 - $num3_sign]

    $final_number = "$number_to_obf $sign1 $number1 $sign2 $number2 $sign3 $number3"
    $out_final = Invoke-Expression $final_number

    $new_problem = "$out_final $opposite_sign1 $number1 $opposite_sign2 $number2 $opposite_sign3 $number3"
    return "($new_problem)"
}