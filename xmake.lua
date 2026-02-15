add_rules("mode.releasedbg")
set_languages("cxx23", "asm")
set_defaultmode("releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
add_requires("nuget::Musa.Veil")

target("kaspersky-hook")
    add_rules("wdk.driver", "wdk.env.kmdf")
    add_defines("NOMINMAX")

    add_syslinks("ntoskrnl", "hal", "wmilib")
    add_files("src/**.cc", "src/**.asm")

    add_packages("nuget::Musa.Veil")
