using System;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Diagnostics
{
    /// <summary>
    /// Entry point and command dispatcher for this project's standalone diagnostic tools - not part
    /// of the Asiri library or its public API. Each command lives in its own class; this file only
    /// ever picks which one to run. See <see cref="CompareCommand"/> for the one command that exists
    /// today.
    /// </summary>
    internal static class Program
    {
        private static Task<int> Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintUsage();
                return Task.FromResult(1);
            }

            var commandArgs = args[1..];
            switch (args[0])
            {
                case "compare":
                    return CompareCommand.RunAsync(commandArgs);
                default:
                    Console.Error.WriteLine($"Unrecognised command '{args[0]}'.");
                    Console.Error.WriteLine();
                    PrintUsage();
                    return Task.FromResult(1);
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: Asiri.Diagnostics <command> [options]");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  compare   Compare Asiri's own decryption of a container against a live VeraCrypt mount.");
            Console.WriteLine();
            Console.WriteLine("Run a command with no further arguments to see its own usage.");
        }
    }
}
