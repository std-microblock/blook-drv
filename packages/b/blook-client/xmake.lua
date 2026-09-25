-- blook-client: the user-mode half of blook-drv, as an xmake repository package.
--
--     add_repositories("blook-repo https://github.com/std-microblock/blook-drv.git")
--     add_requires("blook-client")
--
--     target("mytool")
--         set_kind("binary")
--         add_packages("blook-client")
--
--     #include <client/ept.hpp>
--
-- Same content as sdk/blook-drv-sdk.lua, for projects that prefer a repository
-- over copying a package file. Nothing is vendored: the headers are taken out
-- of the checked out revision.
package("blook-client")
    set_description("User-mode API of blook-drv: EPT hook / hide / scrub session on the BlookDrv device (header-only)")
    set_kind("library", {headeronly = true})

    add_urls("https://github.com/std-microblock/blook-drv.git")
    add_versions("master", "a389a4a6de2ac07d695bed3cf49a5ff3c7460158")

    if is_plat("windows") then
        add_syslinks("advapi32")
    end

    on_install("windows", function (package)
        -- xmake checks the repository out and runs this with that checkout as
        -- the working directory, so the SDK is simply src/ of that revision -
        -- nothing is vendored in this package.
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
