using System.ComponentModel;
using System.Threading;
using System.Windows;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Non-modal (shown via <see cref="Window.Show"/>, not <see cref="Window.ShowDialog"/>) indicator
    /// that a container open is in progress, with a Cancel button that requests cancellation of the
    /// <see cref="CancellationTokenSource"/> the open was started with. Non-modal so the caller can
    /// keep awaiting the open on the same UI thread while this stays responsive; the caller is
    /// expected to disable its own window for the duration instead, since this dialog has no way to
    /// block input to a window it isn't itself modal over.
    ///
    /// Cancellation here is a request, not a guarantee of an immediate stop:
    /// VeraCryptContainer.OpenAsync's brute-force search only checks for cancellation between
    /// algorithms or between PBKDF2 blocks, not partway through a single (up to ~20 second, for
    /// Whirlpool) block, so the operation this cancels may still take a little longer to actually
    /// unwind.
    /// </summary>
    public partial class OpeningProgressDialog : Window
    {
        private readonly CancellationTokenSource _cancellationTokenSource;

        public OpeningProgressDialog(CancellationTokenSource cancellationTokenSource)
        {
            InitializeComponent();
            _cancellationTokenSource = cancellationTokenSource;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource.Cancel();
            CancelButton.IsEnabled = false;
            StatusTextBlock.Text = "Cancelling...";
        }

        /// <summary>
        /// Requests cancellation regardless of how this dialog is dismissed - the Cancel button,
        /// Alt+F4, or the system close box - rather than only when the Cancel button specifically is
        /// clicked. Also fires when the caller closes this dialog itself once the open has already
        /// finished; CancellationTokenSource.Cancel() is safe to call again at that point.
        /// </summary>
        private void OpeningProgressDialog_Closing(object sender, CancelEventArgs e)
        {
            _cancellationTokenSource.Cancel();
        }
    }
}
