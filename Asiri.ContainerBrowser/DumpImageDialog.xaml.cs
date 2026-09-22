using System;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using uk.andyjohnson.Asiri.Export;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog prompting for the output path and format of a
    /// <see cref="FileSystemExtractor.ExportAsync"/> export - the currently open container's
    /// decrypted filesystem, written out unencrypted so it can be examined by tools, people, or a
    /// real OS's own mount path entirely outside Asiri.
    /// </summary>
    public partial class DumpImageDialog : Window
    {
        public DumpImageDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => BrowseButton.Focus();

            FormatComboBox.ItemsSource = Enum.GetValues<FileSystemExportFormat>();
            FormatComboBox.SelectedIndex = 0;
        }

        public FileInfo? OutputPath { get; private set; }

        public FileSystemExportFormat Format => (FileSystemExportFormat)FormatComboBox.SelectedItem;

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var (filter, defaultExt) = Format switch
            {
                FileSystemExportFormat.Vhd or FileSystemExportFormat.VhdWithPartitionTable
                    => ("VHD files (*.vhd)|*.vhd|All files (*.*)|*.*", ".vhd"),
                _ => ("Raw disk images (*.img)|*.img|All files (*.*)|*.*", ".img")
            };

            var dialog = new SaveFileDialog
            {
                Title = "Export Filesystem Image",
                Filter = filter,
                DefaultExt = defaultExt
            };
            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            OutputPath = new FileInfo(dialog.FileName);
            PathTextBox.Text = OutputPath.FullName;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (OutputPath == null)
            {
                MessageBox.Show(this, "Choose where to write the image file.", "No Output File Chosen", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DialogResult = true;
        }
    }
}
