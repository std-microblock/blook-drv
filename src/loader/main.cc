#include <exception>
#include <vector>

#include "cli.hpp"
#include "operations.hpp"
#include "terminal.hpp"

int wmain(int argc, wchar_t** argv) {
    using namespace blook::loader;
    terminal output;
    try {
        std::vector<std::wstring_view> arguments;
        if (argc > 1)
            arguments.reserve(static_cast<std::size_t>(argc - 1));
        for (int i = 1; i < argc; ++i)
            arguments.emplace_back(argv[i]);
        // No Win32 device/service operation is reachable before full
        // validation.
        auto command = cli::parse(arguments);
        if (!command) {
            output.invalid(command.error());
            return 1;
        }
        if (command->action == cli::kind::help) {
            output.help();
            return 0;
        }
        if (command->action == cli::kind::version)
            output.message("Client ABI: " + std::to_string(client_abi()));
        auto result = execute(*command, output);
        if (!result) {
            output.error(result.error());
            return 1;
        }
        if (result->status)
            output.status(*result->status);
        return result->exit_code;
    } catch (const std::exception& error) {
        output.error(failure{
            "Loader", 0, error.what(),
            "The operation could not complete; resources were released."});
        return 1;
    }
}
