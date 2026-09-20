using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog prompting for everything needed to create a brand new VeraCrypt container via
    /// <see cref="VeraCryptContainer.CreateAsync"/>: size, filesystem type, an optional volume label,
    /// whether to enable write access, the password, an optional PIM, optional keyfiles, and the
    /// encryption/hash algorithm to protect it with. Unlike <see cref="CredentialsDialog"/>, the
    /// algorithm and hash choices are never "Unspecified" here - creating a container always requires
    /// a real, explicit choice, the same way the "current credentials" step of the Change Credentials
    /// flow does - but the write-access checkbox itself defaults to checked, unlike
    /// <see cref="CredentialsDialog"/>'s own: a container you just created is, in every realistic
    /// case, about to be populated immediately, matching <c>CreateOptions.AccessMode</c>'s own
    /// default.
    /// </summary>
    public partial class NewContainerDialog : Window
    {
        private readonly ObservableCollection<FileInfo> _keyFiles = new ObservableCollection<FileInfo>();

        public NewContainerDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => BrowseButton.Focus();
            KeyFilesListBox.ItemsSource = _keyFiles;

            FileSystemTypeComboBox.ItemsSource = Enum.GetValues<FileSystemType>();
            FileSystemTypeComboBox.SelectedIndex = 0;

            AlgorithmComboBox.ItemsSource = Enum.GetValues<CryptoAlgorithm>();
            AlgorithmComboBox.SelectedIndex = 0;

            HashAlgorithmComboBox.ItemsSource = Enum.GetValues<HashAlgorithm>();
            HashAlgorithmComboBox.SelectedIndex = 0;
        }

        public FileInfo? ContainerPath { get; private set; }

        public long SizeInBytes { get; private set; }

        public FileSystemType FileSystemType => (FileSystemType)FileSystemTypeComboBox.SelectedItem;

        /// <summary>
        /// Null - meaning let the filesystem's own formatter choose - if left blank. Only enterable
        /// when <see cref="FileSystemType"/> is exFAT: DiscUtils gives no way to override cluster size
        /// for NTFS or FAT at all (see VeraCryptContainer.CreateAsync's own remarks on this), so the
        /// field is disabled rather than let the user set a value CreateAsync would just reject.
        /// </summary>
        public int? ClusterSize { get; private set; }

        /// <summary>Null - meaning no label - if left blank.</summary>
        public string? Label { get; private set; }

        public ContainerAccessMode AccessMode =>
            EnableWriteAccessCheckBox.IsChecked == true ? ContainerAccessMode.ReadWrite : ContainerAccessMode.ReadOnly;

        public string Password => PasswordBoxControl.Password;

        public CryptoAlgorithm Algorithm => (CryptoAlgorithm)AlgorithmComboBox.SelectedItem;

        public HashAlgorithm HashAlgorithm => (HashAlgorithm)HashAlgorithmComboBox.SelectedItem;

        public int Pim { get; private set; }

        public IReadOnlyList<FileInfo> KeyFiles => _keyFiles;

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Title = "Create VeraCrypt Container",
                Filter = "VeraCrypt containers (*.hc)|*.hc|All files (*.*)|*.*",
                DefaultExt = ".hc"
            };
            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            ContainerPath = new FileInfo(dialog.FileName);
            PathTextBox.Text = ContainerPath.FullName;
        }

        private void FileSystemTypeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            ClusterSizeTextBox.IsEnabled = FileSystemType == FileSystemType.ExFat;
            if (!ClusterSizeTextBox.IsEnabled)
            {
                // Cleared, not just disabled - a value typed while exFAT was selected, now sitting
                // greyed-out and unusable for NTFS/FAT, would be confusing to see left behind.
                ClusterSizeTextBox.Text = string.Empty;
            }
        }

        private void AddKeyFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Add Keyfile(s)",
                Multiselect = true
            };
            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            foreach (var fileName in dialog.FileNames)
            {
                if (!_keyFiles.Any(k => k.FullName == fileName))
                {
                    _keyFiles.Add(new FileInfo(fileName));
                }
            }
        }

        private void RemoveKeyFileButton_Click(object sender, RoutedEventArgs e)
        {
            foreach (var selected in KeyFilesListBox.SelectedItems.Cast<FileInfo>().ToList())
            {
                _keyFiles.Remove(selected);
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (ContainerPath == null)
            {
                MessageBox.Show(this, "Choose where to create the container file.", "No Container File Chosen", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!long.TryParse(SizeTextBox.Text.Trim(), out var sizeMB) || sizeMB <= 0)
            {
                MessageBox.Show(this, "Size must be a positive whole number of megabytes.", "Invalid Size", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            SizeInBytes = sizeMB * 1024L * 1024L;

            var pimText = PimTextBox.Text.Trim();
            if (pimText.Length == 0)
            {
                Pim = 0;
            }
            else if (!int.TryParse(pimText, out var pim) || pim < 0)
            {
                MessageBox.Show(this, "PIM must be a non-negative whole number.", "Invalid PIM", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            else
            {
                Pim = pim;
            }

            var clusterSizeText = ClusterSizeTextBox.Text.Trim();
            if (clusterSizeText.Length == 0)
            {
                ClusterSize = null;
            }
            else if (!int.TryParse(clusterSizeText, out var clusterSize) || clusterSize <= 0 || (clusterSize & (clusterSize - 1)) != 0)
            {
                MessageBox.Show(this, "Cluster size must be a positive power of two, in bytes.", "Invalid Cluster Size", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            else
            {
                ClusterSize = clusterSize;
            }

            var labelText = LabelTextBox.Text.Trim();
            Label = labelText.Length == 0 ? null : labelText;

            DialogResult = true;
        }
    }
}
