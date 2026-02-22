Get-ChildItem -Path . -Recurse -Include *.c, *.cpp, *.h, *.hpp, *.cc | ForEach-Object {
    clang-format -i $_.FullName
}