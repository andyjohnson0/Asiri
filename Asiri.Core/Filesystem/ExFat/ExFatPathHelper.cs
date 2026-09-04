namespace uk.andyjohnson.Asiri.Core.Filesystem.ExFat
{
    /// <summary>
    /// Manipulates DiscUtils.ExFat path strings, which are always backslash-separated and rooted at
    /// "\" regardless of the host operating system. Deliberately does not use System.IO.Path, since
    /// Asiri.Core targets non-Windows platforms where the host path conventions differ from exFAT's.
    /// Does not share logic with the NTFS or FAT wrappers' equivalent helpers, so that exFAT-specific
    /// code stays independent of NTFS-specific and FAT-specific code.
    /// </summary>
    internal static class ExFatPathHelper
    {
        public const string Root = "\\";

        /// <summary>
        /// The path separator(s) DiscUtils.ExFat's ExFatFileSystem is configured with.
        /// </summary>
        public static readonly char[] PathSeparators = { '\\' };

        /// <summary>
        /// Extracts the leaf (final path component) name from an exFAT path, e.g.
        /// "\data\subtest.txt" -> "subtest.txt". Returns an empty string for the root path.
        /// </summary>
        public static string GetLeafName(string path)
        {
            var trimmed = path.TrimEnd('\\');
            var lastSeparator = trimmed.LastIndexOf('\\');
            return lastSeparator < 0 ? trimmed : trimmed.Substring(lastSeparator + 1);
        }

        /// <summary>
        /// Combines a directory path with a child name, e.g. ("\data", "subtest.txt") ->
        /// "\data\subtest.txt".
        /// </summary>
        public static string Combine(string directoryPath, string name)
        {
            return directoryPath.EndsWith("\\", System.StringComparison.Ordinal)
                ? directoryPath + name
                : directoryPath + "\\" + name;
        }
    }
}
