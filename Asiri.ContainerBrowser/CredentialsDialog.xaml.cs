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
    /// Modal dialog prompting for the credentials needed to open a VeraCrypt container: the password
    /// (masked, via <see cref="System.Windows.Controls.PasswordBox"/>), an optional PIM, optional
    /// keyfiles, - if the caller already happens to know either - the encryption and/or hash
    /// algorithm, which narrows VeraCryptContainer.OpenAsync's search accordingly instead of it
    /// having to try every combination, and which header region to use (primary, backup, or the
    /// default automatic choice between them). None of these are validated for correctness here -
    /// only the PIM's format, since it must be a number - opening the container is still where a
    /// wrong combination (including a wrongly-guessed algorithm, hash, or header region) is actually
    /// reported.
    /// </summary>
    public partial class CredentialsDialog : Window
    {
        private readonly ObservableCollection<FileInfo> _keyFiles = new ObservableCollection<FileInfo>();

        /// <summary>
        /// Wraps a single ComboBox choice: either a known enum value, or null for "search for it" -
        /// <see cref="object.ToString"/> is what the ComboBox displays, since no DisplayMemberPath is
        /// set in the XAML.
        /// </summary>
        private sealed class AlgorithmOption<T> where T : struct, Enum
        {
            public string Display { get; }
            public T? Value { get; }

            public AlgorithmOption(string display, T? value)
            {
                Display = display;
                Value = value;
            }

            public override string ToString() => Display;
        }

        public CredentialsDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => PasswordBoxControl.Focus();
            KeyFilesListBox.ItemsSource = _keyFiles;

            var algorithmOptions = new List<AlgorithmOption<CryptoAlgorithm>> { new AlgorithmOption<CryptoAlgorithm>("Unspecified", null) };
            algorithmOptions.AddRange(Enum.GetValues<CryptoAlgorithm>().Select(a => new AlgorithmOption<CryptoAlgorithm>(a.ToString(), a)));
            AlgorithmComboBox.ItemsSource = algorithmOptions;
            AlgorithmComboBox.SelectedIndex = 0;

            var hashAlgorithmOptions = new List<AlgorithmOption<HashAlgorithm>> { new AlgorithmOption<HashAlgorithm>("Unspecified", null) };
            hashAlgorithmOptions.AddRange(Enum.GetValues<HashAlgorithm>().Select(h => new AlgorithmOption<HashAlgorithm>(h.ToString(), h)));
            HashAlgorithmComboBox.ItemsSource = hashAlgorithmOptions;
            HashAlgorithmComboBox.SelectedIndex = 0;

            HeaderPreferenceComboBox.ItemsSource = Enum.GetValues<HeaderType>();
            HeaderPreferenceComboBox.SelectedIndex = 0;
        }

        public string Password => PasswordBoxControl.Password;

        public int Pim { get; private set; }

        public IReadOnlyList<FileInfo> KeyFiles => _keyFiles;

        public CryptoAlgorithm? Algorithm => ((AlgorithmOption<CryptoAlgorithm>)AlgorithmComboBox.SelectedItem).Value;

        public HashAlgorithm? HashAlgorithm => ((AlgorithmOption<HashAlgorithm>)HashAlgorithmComboBox.SelectedItem).Value;

        public HeaderType HeaderPreference => (HeaderType)HeaderPreferenceComboBox.SelectedItem;

        public ContainerAccessMode AccessMode =>
            EnableWriteAccessCheckBox.IsChecked == true ? ContainerAccessMode.ReadWrite : ContainerAccessMode.ReadOnly;

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

            DialogResult = true;
        }
    }
}
