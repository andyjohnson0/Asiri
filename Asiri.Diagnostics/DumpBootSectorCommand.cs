using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Diagnostics
{
    /// <summary>
    /// Writes just the first 512 bytes (the boot sector) of a container's decrypted filesystem to a
    /// plain file - a cheap way to eyeball a container's boot sector without pulling in the DiscUtils
    /// virtual-disk dependency <c>Asiri.Export</c>'s real disk-image formats need. Diagnostic-only:
    /// unlike <c>Asiri.Export</c>'s formats, a bare boot sector isn't a usable disk image on its own,
    /// so it has no home there - see <c>Asiri.Export/AGENT.md</c>.
    ///
    /// Opens the container via the ordinary <see cref="VeraCryptContainer.OpenAsync"/> API, then reads
    /// the boot sector through <see cref="IFileSystemExportSource.CopyBytesAsync"/> directly - the
    /// same minimal interface <c>Asiri.Export</c>'s <c>FileSystemExtractor</c> is built on.
    /// </summary>
    internal static class DumpBootSectorCommand
    {
        private const int BootSectorSize = 512;

        private static readonly string[] ValuedOptionNames = { "--pim", "--algorithm", "--hash", "--keyfile" };

        public static async Task<int> RunAsync(string[] args)
        {
            var positional = GetPositionalArgs(args);
            if (positional.Length != 3)
            {
                PrintUsage();
                return 1;
            }

            var containerPath = positional[0];
            var password = positional[1];
            var outputPath = positional[2];

            var pim = GetIntOption(args, "--pim", 0);
            var keyFilePaths = GetStringOptions(args, "--keyfile");
            var keyFiles = keyFilePaths.Count > 0 ? keyFilePaths.Select(p => new FileInfo(p)).ToList() : null;

            CryptoAlgorithm? algorithm = null;
            var algorithmArg = GetStringOption(args, "--algorithm");
            if (algorithmArg != null)
            {
                if (!Enum.TryParse<CryptoAlgorithm>(algorithmArg, ignoreCase: true, out var parsedAlgorithm))
                {
                    Console.Error.WriteLine($"Unrecognised algorithm '{algorithmArg}'. Valid values: {string.Join(", ", Enum.GetNames(typeof(CryptoAlgorithm)))}");
                    return 1;
                }
                algorithm = parsedAlgorithm;
            }

            HashAlgorithm? hashAlgorithm = null;
            var hashArg = GetStringOption(args, "--hash");
            if (hashArg != null)
            {
                if (!Enum.TryParse<HashAlgorithm>(hashArg, ignoreCase: true, out var parsedHash))
                {
                    Console.Error.WriteLine($"Unrecognised hash algorithm '{hashArg}'. Valid values: {string.Join(", ", Enum.GetNames(typeof(HashAlgorithm)))}");
                    return 1;
                }
                hashAlgorithm = parsedHash;
            }

            VeraCryptContainer container;
            try
            {
                container = (await VeraCryptContainer.OpenAsync(
                    new FileInfo(containerPath), password,
                    new OpenOptions { Pim = pim, KeyFiles = keyFiles, Algorithm = algorithm, HashAlgorithm = hashAlgorithm }).ConfigureAwait(false)).Container;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to open the container: {ex.Message}");
                return 1;
            }

            try
            {
                using (var destination = new FileInfo(outputPath).Open(FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await ((IFileSystemExportSource)container).CopyBytesAsync(destination, BootSectorSize, default).ConfigureAwait(false);
                }
            }
            finally
            {
                container.Close();
            }

            Console.WriteLine($"Wrote {BootSectorSize} bytes to {outputPath}.");
            return 0;
        }

        private static string[] GetPositionalArgs(string[] args)
        {
            var positional = new List<string>();
            for (var i = 0; i < args.Length; i++)
            {
                if (ValuedOptionNames.Contains(args[i], StringComparer.OrdinalIgnoreCase))
                {
                    i++; // also skip this option's value, not just the flag itself
                    continue;
                }
                positional.Add(args[i]);
            }
            return positional.ToArray();
        }

        private static int GetIntOption(string[] args, string name, int defaultValue)
        {
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && int.TryParse(args[i + 1], out var value))
                {
                    return value;
                }
            }
            return defaultValue;
        }

        private static string? GetStringOption(string[] args, string name)
        {
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return args[i + 1];
                }
            }
            return null;
        }

        private static IReadOnlyList<string> GetStringOptions(string[] args, string name)
        {
            var values = new List<string>();
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    values.Add(args[i + 1]);
                }
            }
            return values;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: Asiri.Diagnostics dump-boot-sector <containerPath> <password> <outputPath> [--pim N] [--algorithm X] [--hash X] [--keyfile path]...");
            Console.WriteLine();
            Console.WriteLine($"  algorithm: {string.Join(", ", Enum.GetNames(typeof(CryptoAlgorithm)))} (omit to auto-detect)");
            Console.WriteLine($"  hash:      {string.Join(", ", Enum.GetNames(typeof(HashAlgorithm)))} (omit to auto-detect)");
            Console.WriteLine("  --keyfile: Path to a keyfile mixed into the password. Repeatable for more than one keyfile.");
            Console.WriteLine();
            Console.WriteLine("Writes the first 512 bytes (the boot sector) of the container's decrypted filesystem to");
            Console.WriteLine("outputPath, for a cheap look at just that without needing Asiri.Export's VHD-family");
            Console.WriteLine("formats.");
        }
    }
}
