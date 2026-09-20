using System.ComponentModel;
using System.Threading;
using System.Windows;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Non-modal (shown via <see cref="Window.Show"/>, not <see cref="Window.ShowDialog"/>) indicator
    /// that a cancellable, potentially slow Asiri.Core operation is in progress - opening a container,
    /// importing files, or moving a large one - with a Cancel button that requests cancellation of the
    /// <see cref="CancellationTokenSource"/> the operation was started with. Non-modal so the caller
    /// can keep awaiting the operation on the same UI thread while this stays responsive; the caller
    /// is expected to disable its own window for the duration instead, since this dialog has no way to
    /// block input to a window it isn't itself modal over.
    ///
    /// Cancellation here is a request, not a guarantee of an immediate stop: the underlying operation
    /// may only check for cancellation between coarse-grained steps (e.g. VeraCryptContainer.OpenAsync's
    /// brute-force search checks between algorithms or PBKDF2 blocks, not partway through a single
    /// block), so the operation this cancels may still take a little longer to actually unwind.
    /// </summary>
    public partial class ProgressDialog : Window
    {
        private readonly CancellationTokenSource _cancellationTokenSource;

        public ProgressDialog(CancellationTokenSource cancellationTokenSource, string statusMessage = "Working...")
        {
            InitializeComponent();
            _cancellationTokenSource = cancellationTokenSource;
            StatusTextBlock.Text = statusMessage;
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
        /// clicked. Also fires when the caller closes this dialog itself once the operation has
        /// already finished; CancellationTokenSource.Cancel() is safe to call again at that point.
        /// </summary>
        private void ProgressDialog_Closing(object sender, CancelEventArgs e)
        {
            _cancellationTokenSource.Cancel();
        }
    }
}
