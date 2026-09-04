using System.Windows;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal dialog prompting for a container password. Masked input via <see cref="System.Windows.Controls.PasswordBox"/>.
    /// </summary>
    public partial class PasswordDialog : Window
    {
        public PasswordDialog()
        {
            InitializeComponent();
            Loaded += (_, _) => PasswordBoxControl.Focus();
        }

        public string Password => PasswordBoxControl.Password;

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }
    }
}
