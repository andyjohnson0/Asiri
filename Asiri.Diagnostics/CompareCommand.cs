using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Diagnostics
{
    /// <summary>
    /// Answers one question conclusively, in a single run, instead of two people separately eyeballing
    /// hex dumps: when a real VeraCrypt mounts an Asiri-created container but Windows won't recognise
    /// its filesystem, does VeraCrypt's own decryption of the data area disagree with Asiri's, or are
    /// the decrypted bytes identical and the problem lies somewhere downstream of decryption entirely
    /// (e.g. how the mounted volume presents its size/geometry to Windows)?
    ///
    /// Decrypts the container's data area directly via <see cref="HeaderParser"/> and
    /// <see cref="SectorDecryptor"/> - never through <see cref="VeraCryptContainer"/> or DiscUtils, so
    /// no filesystem interpretation is involved on Asiri's side either - and compares the result
    /// byte-for-byte against the same byte range read raw off the drive letter a real, already-running
    /// VeraCrypt has mounted that same container onto.
    /// </summary>
    internal static class CompareCommand
    {
        private static readonly string[] ValuedOptionNames = { "--bytes", "--pim", "--keyfile" };

        public static async Task<int> RunAsync(string[] args)
        {
            var positional = GetPositionalArgs(args);
            if (positional.Length != 5)
            {
                PrintUsage();
                return 1;
            }

            var containerPath = positional[0];
            var password = positional[1];
            var algorithmArg = positional[2];
            var hashAlgorithmArg = positional[3];
            var driveLetter = positional[4];

            var byteCount = GetIntOption(args, "--bytes", 4096);
            var pim = GetIntOption(args, "--pim", 0);
            var keyFilePaths = GetStringOptions(args, "--keyfile");
            var keyFiles = keyFilePaths.Count > 0 ? keyFilePaths.Select(p => new FileInfo(p)).ToList() : null;

            if (!Enum.TryParse<CryptoAlgorithm>(algorithmArg, ignoreCase: true, out var algorithm))
            {
                Console.Error.WriteLine($"Unrecognised algorithm '{algorithmArg}'. Valid values: {string.Join(", ", Enum.GetNames(typeof(CryptoAlgorithm)))}");
                return 1;
            }
            if (!Enum.TryParse<HashAlgorithm>(hashAlgorithmArg, ignoreCase: true, out var hashAlgorithm))
            {
                Console.Error.WriteLine($"Unrecognised hash algorithm '{hashAlgorithmArg}'. Valid values: {string.Join(", ", Enum.GetNames(typeof(HashAlgorithm)))}");
                return 1;
            }

            byte[] asiriView;
            VeraCryptHeader header;
            try
            {
                header = await HeaderParser.ParseAsync(containerPath, password, algorithm, hashAlgorithm, pim, keyFiles).ConfigureAwait(false);
                using (var decryptor = await SectorDecryptor.CreateAsync(containerPath, header, canWrite: false).ConfigureAwait(false))
                {
                    var clamped = (int)Math.Min(byteCount, decryptor.SectorCount * decryptor.SectorSize);
                    asiriView = await decryptor.ReadDecryptedAsync(0, clamped).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to decrypt the container via Asiri: {ex.Message}");
                return 1;
            }

            Console.WriteLine($"Asiri header: VolumeSize={header.VolumeSize}, EncryptedAreaSize={header.EncryptedAreaSize}, SectorSize={header.SectorSize}, MasterKeyScopeOffset={header.MasterKeyScopeOffset}");
            Console.WriteLine($"Decrypted {asiriView.Length} bytes ({asiriView.Length / 512} sectors) at offset 0 of the volume via Asiri.");
            Console.WriteLine();
            PrintBootSectorSummary("Asiri-decrypted view", asiriView);
            Console.WriteLine();

            // Before comparing decrypted bytes at all: is the drive letter even backed by the size of
            // volume Asiri thinks this container is? A mismatch here means either the drive letter
            // isn't actually this container (a stale mount, a copy that no longer matches, etc.), or -
            // as turned out to be the real bug the first time this tool was used - VeraCrypt itself is
            // computing a different size for a reason worth its own investigation (e.g. treating the
            // volume as legacy-format). Either way, a byte-level MISMATCH below should be read in light
            // of this, not assumed on its own to mean a decryption bug.
            var rawVolumeLength = TryGetRawVolumeLength(driveLetter);
            if (rawVolumeLength.HasValue)
            {
                Console.WriteLine($"Raw volume {driveLetter} reports a length of {rawVolumeLength.Value:N0} bytes (Asiri's own VolumeSize: {header.VolumeSize:N0}).");
                if (rawVolumeLength.Value != header.VolumeSize)
                {
                    Console.WriteLine("WARNING: these sizes do not match. Either the drive letter is not backed by");
                    Console.WriteLine("the same container this command just decrypted, or VeraCrypt is computing a");
                    Console.WriteLine("different size for this container for some other reason - a byte mismatch below");
                    Console.WriteLine("should not be assumed to be a decryption bug until this is resolved.");
                }
            }
            else
            {
                Console.WriteLine($"NOTE: could not query the raw volume's own reported length at drive {driveLetter}; proceeding without this cross-check.");
            }
            Console.WriteLine();

            byte[] veraView;
            try
            {
                veraView = ReadRawVolume(driveLetter, asiriView.Length);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to read the raw volume at drive {driveLetter}: {ex.Message}");
                Console.Error.WriteLine("This needs an elevated (Administrator) process, and the drive letter a real, currently-running VeraCrypt actually assigned to the mounted container.");
                return 1;
            }

            PrintBootSectorSummary("Raw VeraCrypt-mounted view", veraView);
            Console.WriteLine();

            if (veraView.Length != asiriView.Length)
            {
                Console.WriteLine($"NOTE: only read {veraView.Length} of {asiriView.Length} requested bytes from the raw volume (short read, or the mounted volume is smaller than expected).");
            }

            var compareLength = Math.Min(asiriView.Length, veraView.Length);
            var firstDiff = -1;
            var diffCount = 0;
            for (var i = 0; i < compareLength; i++)
            {
                if (asiriView[i] != veraView[i])
                {
                    if (firstDiff < 0)
                    {
                        firstDiff = i;
                    }
                    diffCount++;
                }
            }

            if (firstDiff < 0 && veraView.Length == asiriView.Length)
            {
                Console.WriteLine("RESULT: IDENTICAL. VeraCrypt is decrypting this container's data area exactly as Asiri does.");
                Console.WriteLine("The problem is downstream of decryption - e.g. how the volume presents its size/geometry to Windows - not the crypto.");
                return 0;
            }

            Console.WriteLine($"RESULT: MISMATCH. First differing byte at offset {firstDiff} ({diffCount} of {compareLength} compared bytes differ).");
            Console.WriteLine();
            PrintHexDumpAround("Asiri-decrypted", asiriView, Math.Max(firstDiff, 0));
            PrintHexDumpAround("Raw VeraCrypt-mounted", veraView, Math.Max(firstDiff, 0));

            return 2;
        }

        /// <summary>
        /// Every positional argument, in order, with each recognised valued option (its flag and the
        /// single token following it) removed. Filtering purely on "does this token start with --",
        /// as this used to do, only ever removed the flag itself - an option's own value (e.g. the
        /// "4096" in "--bytes 4096", or any keyfile path, which never starts with "--") was left
        /// behind and miscounted as a positional argument. Never noticed before because nothing had
        /// actually exercised --bytes/--pim with a real invocation; adding --keyfile hit it immediately.
        /// </summary>
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

        /// <summary>
        /// Every value following a (possibly repeated) occurrence of <paramref name="name"/> - used
        /// for --keyfile, which unlike --bytes/--pim can legitimately be supplied more than once.
        /// </summary>
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
            Console.WriteLine("Usage: Asiri.Diagnostics compare <containerPath> <password> <algorithm> <hashAlgorithm> <driveLetter> [--bytes N] [--pim N] [--keyfile path]...");
            Console.WriteLine();
            Console.WriteLine($"  algorithm:     {string.Join(", ", Enum.GetNames(typeof(CryptoAlgorithm)))}");
            Console.WriteLine($"  hashAlgorithm: {string.Join(", ", Enum.GetNames(typeof(HashAlgorithm)))}");
            Console.WriteLine("  driveLetter:   The drive letter (e.g. E or E:) that a real, already-running VeraCrypt");
            Console.WriteLine("                 has mounted the SAME container onto. Reading it raw requires this");
            Console.WriteLine("                 process to be run as Administrator.");
            Console.WriteLine("  --keyfile:     Path to a keyfile mixed into the password, exactly like VeraCrypt's own");
            Console.WriteLine("                 keyfiles. Repeatable for more than one keyfile, applied in the order given.");
            Console.WriteLine();
            Console.WriteLine("Decrypts the container's data area directly via Asiri.Core (no filesystem involved on");
            Console.WriteLine("Asiri's side) and compares it byte-for-byte against the same range read raw off the");
            Console.WriteLine("VeraCrypt-mounted drive, to determine whether VeraCrypt's own decryption agrees with");
            Console.WriteLine("Asiri's, or whether the mismatch lies somewhere else entirely.");
        }

        private static void PrintBootSectorSummary(string label, byte[] data)
        {
            Console.WriteLine($"{label}:");
            if (data.Length < 64)
            {
                Console.WriteLine("  (too short to decode a boot sector)");
                return;
            }

            var oemId = Encoding.ASCII.GetString(data, 3, 8).TrimEnd();
            var signaturePresent = data.Length >= 512 && data[510] == 0x55 && data[511] == 0xAA;

            if (oemId == "EXFAT")
            {
                PrintExFatSummary(data, signaturePresent);
                return;
            }

            var bytesPerSector = BitConverter.ToUInt16(data, 11);
            var sectorsPerCluster = data[13];

            Console.WriteLine($"  OEM ID: \"{oemId}\"   BytesPerSector: {bytesPerSector}   SectorsPerCluster: {sectorsPerCluster}   BootSignature0x55AA: {signaturePresent}");

            if (oemId == "NTFS")
            {
                // NTFS BPB: 8-byte TotalSectors at offset 40, 8-byte (cluster-relative) MFT start at 48.
                var totalSectors = BitConverter.ToInt64(data, 40);
                var mftStartCluster = BitConverter.ToInt64(data, 48);
                Console.WriteLine($"  NTFS: TotalSectors={totalSectors} ({(long)totalSectors * Math.Max(bytesPerSector, (ushort)1):N0} bytes declared)   MftStartCluster={mftStartCluster}");
            }
        }

        /// <summary>
        /// exFAT's Main Boot Sector shares only the jump instruction, file-system name, and boot
        /// signature layout with the classic FAT/NTFS BPB - verified against Microsoft's own exFAT
        /// specification, everything from byte 11 onward is laid out completely differently. Bytes
        /// 11-63 (where the generic decode above reads "BytesPerSector"/"SectorsPerCluster") are
        /// required to be zero in exFAT, and the real sector/cluster sizes are stored as power-of-two
        /// shifts at bytes 108/109 instead of direct values - reusing the generic decode for exFAT
        /// would print misleadingly wrong (near-zero) values for a perfectly valid boot sector.
        /// </summary>
        private static void PrintExFatSummary(byte[] data, bool signaturePresent)
        {
            if (data.Length < 100)
            {
                Console.WriteLine($"  OEM ID: \"EXFAT\"   BootSignature0x55AA: {signaturePresent}   (too short to decode exFAT-specific fields)");
                return;
            }

            var bytesPerSector = 1 << data[108];
            var sectorsPerCluster = 1 << data[109];

            Console.WriteLine($"  OEM ID: \"EXFAT\"   BytesPerSector: {bytesPerSector}   SectorsPerCluster: {sectorsPerCluster}   BootSignature0x55AA: {signaturePresent}");

            var volumeLengthSectors = BitConverter.ToInt64(data, 72);
            var clusterCount = BitConverter.ToUInt32(data, 92);
            var firstClusterOfRootDirectory = BitConverter.ToUInt32(data, 96);
            Console.WriteLine($"  exFAT: VolumeLength={volumeLengthSectors} sectors ({volumeLengthSectors * bytesPerSector:N0} bytes declared)   ClusterCount={clusterCount}   FirstClusterOfRootDirectory={firstClusterOfRootDirectory}");
        }

        private static void PrintHexDumpAround(string label, byte[] data, int centerOffset)
        {
            const int context = 32;
            var start = Math.Max(0, centerOffset - context);
            var end = Math.Min(data.Length, centerOffset + context);

            Console.WriteLine($"{label}, bytes {start}-{end - 1}:");
            for (var row = start - (start % 16); row < end; row += 16)
            {
                var sb = new StringBuilder();
                sb.Append($"  {row:X8}: ");
                for (var col = 0; col < 16; col++)
                {
                    var idx = row + col;
                    sb.Append(idx >= start && idx < data.Length ? data[idx].ToString("X2") : "  ").Append(' ');
                }
                Console.WriteLine(sb.ToString());
            }
            Console.WriteLine();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        private const uint IoctlDiskGetLengthInfo = 0x0007405C;

        /// <summary>
        /// Queries a mounted volume's own reported length directly from the disk/volume stack, via
        /// IOCTL_DISK_GET_LENGTH_INFO. Unlike a regular file's <see cref="FileStream.Length"/>, this
        /// works even for a RAW, filesystem-unrecognised volume - exactly the case this tool exists to
        /// diagnose - since it asks the volume layer directly rather than going through any filesystem
        /// driver. No managed equivalent exists for this control code, hence the P/Invoke here (unlike
        /// <see cref="ReadRawVolume"/>'s plain read, which needed none). Returns null if the query
        /// fails for any reason: this is a diagnostic cross-check, not worth failing the whole command
        /// over if it can't be answered.
        /// </summary>
        private static long? TryGetRawVolumeLength(string driveLetter)
        {
            var letter = driveLetter.TrimEnd(':', '\\');
            var path = $@"\\.\{letter}:";

            try
            {
                using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buffer = Marshal.AllocHGlobal(sizeof(long));
                try
                {
                    if (!DeviceIoControl(handle, IoctlDiskGetLengthInfo, IntPtr.Zero, 0, buffer, sizeof(long), out _, IntPtr.Zero))
                    {
                        return null;
                    }
                    return Marshal.ReadInt64(buffer);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Reads the first <paramref name="byteCount"/> bytes raw off a mounted volume's drive
        /// letter - i.e. exactly what VeraCrypt itself decrypted and handed to Windows, with no
        /// filesystem driver involved (Windows treats an unrecognised volume as RAW, which still
        /// allows this kind of direct read). Requires an elevated process: opening a volume for raw
        /// access is an administrative operation in Windows regardless of the underlying file's own
        /// permissions - confirmed empirically (rather than assumed) that <see cref="File.OpenHandle"/>
        /// passes a "\\.\" device path straight through to Win32 with no extra validation of its own,
        /// so a plain managed call works here exactly as well as a P/Invoke to CreateFile would, and
        /// surfaces the same underlying errors (no such drive, access denied) as ordinary .NET
        /// exceptions instead of a raw Win32 error code this method would otherwise have to translate.
        /// </summary>
        private static byte[] ReadRawVolume(string driveLetter, int byteCount)
        {
            var letter = driveLetter.TrimEnd(':', '\\');
            var path = $@"\\.\{letter}:";

            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var stream = new FileStream(handle, FileAccess.Read);
            var buffer = new byte[byteCount];
            var totalRead = 0;
            while (totalRead < byteCount)
            {
                var read = stream.Read(buffer, totalRead, byteCount - totalRead);
                if (read == 0)
                {
                    break;
                }
                totalRead += read;
            }

            if (totalRead < byteCount)
            {
                Array.Resize(ref buffer, totalRead);
            }
            return buffer;
        }
    }
}
