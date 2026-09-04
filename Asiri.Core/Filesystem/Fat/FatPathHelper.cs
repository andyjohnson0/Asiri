namespace uk.andyjohnson.Asiri.Core.Filesystem.Fat
{
    /// <summary>
    /// Manipulates DiscUtils.Fat path strings, which are always backslash-separated and rooted at
    /// "\" regardless of the host operating system. Deliberately does not use System.IO.Path, since
    /// Asiri.Core targets non-Windows platforms where the host path conventions differ from FAT's.
    /// Does not share logic with the NTFS wrapper's equivalent helper, so that FAT-specific code
    /// stays independent of NTFS-specific code.
    /// </summary>
    internal static class FatPathHelper
    {
        public const string Root = "\\";

        /// <summary>
        /// Extracts the leaf (final path component) name from a FAT path, e.g.
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
