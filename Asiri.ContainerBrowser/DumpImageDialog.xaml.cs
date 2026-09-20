using System;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog prompting for the output path and format of a
    /// <see cref="VeraCryptContainer.DumpRawImageAsync"/> export - the currently open container's
    /// decrypted filesystem, written out unencrypted so it can be examined by tools, people, or a
    /// real OS's own mount path entirely outside Asiri.
    /// </summary>
    public partial class DumpImageDialog : Window
    {
        public DumpImageDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => BrowseButton.Focus();

            FormatComboBox.ItemsSource = Enum.GetValues<RawImageExportFormat>();
            FormatComboBox.SelectedIndex = 0;
        }

        public FileInfo? OutputPath { get; private set; }

        public RawImageExportFormat Format => (RawImageExportFormat)FormatComboBox.SelectedItem;

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var (filter, defaultExt) = Format switch
            {
                RawImageExportFormat.Vhd or RawImageExportFormat.VhdWithPartitionTable
                    => ("VHD files (*.vhd)|*.vhd|All files (*.*)|*.*", ".vhd"),
                _ => ("Raw disk images (*.img)|*.img|All files (*.*)|*.*", ".img")
            };

            var dialog = new SaveFileDialog
            {
                Title = "Dump Raw Filesystem Image",
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
