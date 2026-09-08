using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog prompting for the credentials needed to open a VeraCrypt container: the password
    /// (masked, via <see cref="System.Windows.Controls.PasswordBox"/>), an optional PIM, and optional
    /// keyfiles. None of these are validated for correctness here - only the PIM's format, since it
    /// must be a number - opening the container is still where a wrong combination is actually
    /// reported.
    /// </summary>
    public partial class CredentialsDialog : Window
    {
        private readonly ObservableCollection<FileInfo> _keyFiles = new ObservableCollection<FileInfo>();

        public CredentialsDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => PasswordBoxControl.Focus();
            KeyFilesListBox.ItemsSource = _keyFiles;
        }

        public string Password => PasswordBoxControl.Password;

        public int Pim { get; private set; }

        public IReadOnlyList<FileInfo> KeyFiles => _keyFiles;

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
