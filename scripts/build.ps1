$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
New-Item -Force -ItemType Directory build/main, build/test | Out-Null
$main = @(Get-ChildItem -Path src/main/java -Filter *.java -Recurse | ForEach-Object FullName)
& javac -encoding UTF-8 --release 17 -d build/main $main
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
$tests = @(Get-ChildItem -Path src/test/java -Filter *.java -Recurse | ForEach-Object FullName)
# Compile tests with the application sources together. This avoids Windows
# javac classpath resolution failures for the space-containing repo path.
& javac -encoding UTF-8 --release 17 -d build/test ($main + $tests)
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
