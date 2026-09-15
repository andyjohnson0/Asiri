using System.Windows;
using System.Windows.Controls;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// A generic single-line text prompt, modal via <see cref="Window.ShowDialog()"/> like
    /// <see cref="CredentialsDialog"/>. Used for New Subdirectory/New File names and for Rename.
    /// The library itself is the source of truth for whether a name is valid - this dialog only
    /// stops an obviously-empty submission; anything else invalid is reported when the caller's own
    /// Asiri.Core call throws.
    /// </summary>
    public partial class TextInputDialog : Window
    {
        public TextInputDialog(string title, string prompt, string initialValue = "")
        {
            InitializeComponent();
            Title = title;
            PromptTextBlock.Text = prompt;
            InputTextBox.Text = initialValue;
            Loaded += (_, _) =>
            {
                InputTextBox.Focus();
                InputTextBox.SelectAll();
            };
        }

        public string Value { get; private set; } = string.Empty;

        private void InputTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            OkButton.IsEnabled = InputTextBox.Text.Trim().Length > 0;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Value = InputTextBox.Text.Trim();
            DialogResult = true;
        }
    }
}
