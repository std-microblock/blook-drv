-- blook-drv SDK, as an xmake package description (no sources live here).
--
-- Copy this file into your project and include it:
--
--     includes("deps/blook-drv-sdk.lua")
--     add_requires("blook-drv-sdk")
--
--     target("mytool")
--         set_kind("binary")
--         add_packages("blook-drv-sdk")
--
--     #include <client/ept.hpp>
--
-- xmake clones the driver repository and installs the user-mode half of it:
-- src/client (the session / hook API), src/ipc (the IOCTL ABI) and
-- src/policy (the pure policy headers). The driver itself is not built or
-- loaded by this package - see sdk/README.md.
--
-- Alternatively add the repository itself and use packages/b/blook-client:
--
--     add_repositories("blook-repo https://github.com/std-microblock/blook-drv.git")
--     add_requires("blook-client")
package("blook-drv-sdk")
    set_description("User-mode SDK of blook-drv: EPT hook / hide / scrub session on the BlookDrv device")
    set_kind("library", {headeronly = true})

    add_urls("https://github.com/std-microblock/blook-drv.git")

    if is_plat("windows") then
        add_syslinks("advapi32")
    end

    on_install("windows", function (package)
        assert(os.isfile("src/client/ept.hpp"), "src/client is missing from the checked out revision")
        for _, dir in ipairs({"client", "ipc", "policy"}) do
            os.cp(path.join("src", dir), package:installdir("include"))
        end
    end)

    on_test(function (package)
        assert(package:check_cxxsnippets({test = [[
            #include <client/ept.hpp>
            static void probe() {
                auto session = blook::client::session::open(false);
                if (session) { auto info = session->query(); (void)info; }
            }
        ]]}, {configs = {languages = "cxx23", cxflags = "/EHsc"}}))
    end)
