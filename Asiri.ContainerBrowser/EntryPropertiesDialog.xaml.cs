using System;
using System.IO;
using System.Windows;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog (same <see cref="Window.ShowDialog()"/> pattern as <see cref="CredentialsDialog"/>)
    /// for viewing, and - when <paramref name="readOnly"/> is false - editing, a filesystem entry's
    /// attributes and UTC timestamps. Pre-populated by the caller from the entry's current values
    /// before showing. Only the four attributes meaningful to toggle by hand are exposed -
    /// <see cref="FileAttributes.Directory"/>, <see cref="FileAttributes.Normal"/>, and the rest
    /// aren't user-togglable here. Timestamps are edited as free text and parsed with
    /// <see cref="DateTime.TryParse(string, out DateTime)"/>, warning and staying open on failure -
    /// the same pattern <see cref="CredentialsDialog"/> uses for its PIM field.
    /// </summary>
    public partial class EntryPropertiesDialog : Window
    {
        private readonly bool _readOnly;

        public EntryPropertiesDialog(string entryName, FileAttributes currentAttributes, DateTime currentCreationTimeUtc,
            DateTime currentLastWriteTimeUtc, bool readOnly = false)
        {
            InitializeComponent();
            Title = $"Properties: {entryName}";
            _readOnly = readOnly;

            ReadOnlyCheckBox.IsChecked = currentAttributes.HasFlag(FileAttributes.ReadOnly);
            HiddenCheckBox.IsChecked = currentAttributes.HasFlag(FileAttributes.Hidden);
            SystemCheckBox.IsChecked = currentAttributes.HasFlag(FileAttributes.System);
            ArchiveCheckBox.IsChecked = currentAttributes.HasFlag(FileAttributes.Archive);

            CreationTimeTextBox.Text = currentCreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss");
            LastWriteTimeTextBox.Text = currentLastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss");

            if (readOnly)
            {
                ReadOnlyCheckBox.IsEnabled = false;
                HiddenCheckBox.IsEnabled = false;
                SystemCheckBox.IsEnabled = false;
                ArchiveCheckBox.IsEnabled = false;
                CreationTimeTextBox.IsEnabled = false;
                LastWriteTimeTextBox.IsEnabled = false;
                OkButton.Content = "Close";
                CancelButton.Visibility = Visibility.Collapsed;
            }
        }

        public FileAttributes ResultAttributes { get; private set; }

        public DateTime ResultCreationTimeUtc { get; private set; }

        public DateTime ResultLastWriteTimeUtc { get; private set; }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (_readOnly)
            {
                // Nothing to validate or apply - the caller never reads Result* when it opened this
                // dialog read-only in the first place.
                DialogResult = true;
                return;
            }

            if (!DateTime.TryParse(CreationTimeTextBox.Text, out var creationTimeUtc))
            {
                MessageBox.Show(this, "Creation time is not a valid date/time.", "Invalid creation time", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!DateTime.TryParse(LastWriteTimeTextBox.Text, out var lastWriteTimeUtc))
            {
                MessageBox.Show(this, "Last write time is not a valid date/time.", "Invalid last write time", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var attributes = FileAttributes.Normal;
            if (ReadOnlyCheckBox.IsChecked == true) attributes |= FileAttributes.ReadOnly;
            if (HiddenCheckBox.IsChecked == true) attributes |= FileAttributes.Hidden;
            if (SystemCheckBox.IsChecked == true) attributes |= FileAttributes.System;
            if (ArchiveCheckBox.IsChecked == true) attributes |= FileAttributes.Archive;
            if (attributes != FileAttributes.Normal)
            {
                attributes &= ~FileAttributes.Normal;
            }

            ResultAttributes = attributes;
            ResultCreationTimeUtc = DateTime.SpecifyKind(creationTimeUtc, DateTimeKind.Utc);
            ResultLastWriteTimeUtc = DateTime.SpecifyKind(lastWriteTimeUtc, DateTimeKind.Utc);
            DialogResult = true;
        }
    }
}
