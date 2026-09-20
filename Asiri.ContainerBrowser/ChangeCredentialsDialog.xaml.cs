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
    /// Modal dialog prompting for the "new credentials" half of the Change Credentials flow: the new
    /// password, an optional new PIM, optional new keyfiles, and - only if the checkbox is ticked -
    /// a different hash algorithm. Unlike <see cref="CredentialsDialog"/>, there is no encryption
    /// algorithm choice at all here: <c>VeraCryptContainer.ChangeCredentialsAsync</c> can never
    /// change it, so there is nothing to ask about.
    /// </summary>
    public partial class ChangeCredentialsDialog : Window
    {
        private readonly ObservableCollection<FileInfo> _keyFiles = new ObservableCollection<FileInfo>();

        public ChangeCredentialsDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => NewPasswordBoxControl.Focus();
            NewKeyFilesListBox.ItemsSource = _keyFiles;

            NewHashAlgorithmComboBox.ItemsSource = Enum.GetValues<HashAlgorithm>();
            NewHashAlgorithmComboBox.SelectedIndex = 0;
        }

        public string NewPassword => NewPasswordBoxControl.Password;

        public int NewPim { get; private set; }

        public IReadOnlyList<FileInfo> NewKeyFiles => _keyFiles;

        /// <summary>
        /// Null - meaning "keep the current hash algorithm", the same convention
        /// <see cref="ChangeCredentialsOptions.NewHashAlgorithm"/> uses - unless
        /// <see cref="ChangeHashAlgorithmCheckBox"/> is ticked.
        /// </summary>
        public HashAlgorithm? NewHashAlgorithm =>
            ChangeHashAlgorithmCheckBox.IsChecked == true ? (HashAlgorithm)NewHashAlgorithmComboBox.SelectedItem : null;

        private void ChangeHashAlgorithmCheckBox_CheckedChanged(object sender, RoutedEventArgs e)
        {
            NewHashAlgorithmComboBox.IsEnabled = ChangeHashAlgorithmCheckBox.IsChecked == true;
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
            foreach (var selected in NewKeyFilesListBox.SelectedItems.Cast<FileInfo>().ToList())
            {
                _keyFiles.Remove(selected);
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            var pimText = NewPimTextBox.Text.Trim();
            if (pimText.Length == 0)
            {
                NewPim = 0;
            }
            else if (!int.TryParse(pimText, out var pim) || pim < 0)
            {
                MessageBox.Show(this, "PIM must be a non-negative whole number.", "Invalid PIM", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            else
            {
                NewPim = pim;
            }

            DialogResult = true;
        }
    }
}
