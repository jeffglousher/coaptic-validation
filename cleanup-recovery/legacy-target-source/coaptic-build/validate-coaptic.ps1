param([Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]+$')][string]$Stem, [ValidateRange(1,17)][int]$StartAt=1)
$env:CARGO_TARGET_DIR='D:\coaptic-build'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_PROFILE_DEV_DEBUG='0'
$env:CARGO_PROFILE_TEST_DEBUG='0'
$env:PYTHONUTF8='1'
$checks=@('fmt --all -- --check','clippy --all-targets --all-features -- -D warnings','clippy --all-targets --no-default-features -- -D warnings','clippy -p coaptic-plugtest --all-targets --features dtls,oscore -- -D warnings','test --no-default-features','test --all-features','test --no-default-features --features alloc','test --no-default-features --features oscore','test --no-default-features --features alloc,oscore','test --no-default-features --features std','test -p coaptic-plugtest --features dtls,oscore','doc --no-deps --all-features','package -p coaptic --locked','+1.85.0 check --locked -p coaptic --no-default-features','+1.85.0 check --locked -p coaptic --all-features','run -p coaptic-plugtest --bin dogfood -- --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood.json','run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood-oscore.json')
$i=0
foreach($check in $checks){ $i++; if($i -lt $StartAt){ continue }; $argsForCargo=$check.Split(' '); $log="D:\coaptic-build\$Stem-validation-$i.log"; & cargo @argsForCargo *> $log; if($LASTEXITCODE -ne 0){ Get-Content -LiteralPath $log -Tail 40; exit 1 }; Write-Output "PASS $i $check" }
