add_rules("mode.releasedbg")
set_languages("cxx23")
set_defaultmode("releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
add_requires("nuget::Musa.Veil")

--
-- Core library (utilities, pattern matching, PE parsing, etc.)
--
target("core")
    add_rules("wdk.env.kmdf")
    set_kind("static")
    add_defines("NOMINMAX", "_KERNEL_MODE")
    
    add_files("src/core/*.cc")
    add_headerfiles("src/core/*.hpp")
    add_includedirs("src", {public = true})
    add_packages("nuget::Musa.Veil")

--
-- SSDT Hook library (depends on core)
--
target("ssdt")
    add_rules("wdk.env.kmdf")
    set_kind("static")
    add_defines("NOMINMAX", "_KERNEL_MODE")
    
    add_files("src/ssdt/*.cc")
    add_headerfiles("src/ssdt/*.hpp")
    
    add_includedirs("src", {public = true})
    add_packages("nuget::Musa.Veil")
    add_deps("core")

--
-- Main driver (blook-drv)
--
target("blook-drv")
    add_rules("wdk.driver", "wdk.env.kmdf")
    add_defines("NOMINMAX", "_KERNEL_MODE")
    
    add_syslinks("ntoskrnl", "hal", "wmilib")
    add_files("src/driver/*.cc")
    
    add_includedirs("src")
    add_packages("nuget::Musa.Veil")
    add_deps("core", "ssdt")

--
-- User-mode loader (blook-loader)
--
target("blook-loader")
    set_kind("binary")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    
    add_files("src/loader/*.cc")
    add_includedirs("src")
    add_syslinks("advapi32")

