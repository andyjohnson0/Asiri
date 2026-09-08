using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Main window: a classic two-pane VeraCrypt container browser. The left pane is a lazily-loaded
    /// tree of the open container's folders and files; the right pane shows the selected file's
    /// content, as an image, as text, or as a hex dump, depending on its type.
    /// </summary>
    public partial class MainWindow : Window
    {
        private VeraCryptContainer? _container;

        public MainWindow()
        {
            InitializeComponent();
            Closing += (_, _) => _container?.Close();
        }

        private async void OpenMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Title = "Open VeraCrypt Container",
                Filter = "VeraCrypt containers (*.hc)|*.hc|All files (*.*)|*.*"
            };
            if (openDialog.ShowDialog(this) != true)
            {
                return;
            }

            var credentialsDialog = new CredentialsDialog { Owner = this };
            if (credentialsDialog.ShowDialog() != true)
            {
                return;
            }

            OpenMenuItem.IsEnabled = false;
            try
            {
                _container = await VeraCryptContainer.OpenAsync(
                    new FileInfo(openDialog.FileName), credentialsDialog.Password, credentialsDialog.Pim, credentialsDialog.KeyFiles);

                ClearContentPane();
                await LoadRootAsync();

                CloseMenuItem.IsEnabled = true;
                StatusText.Text = $"Opened: {openDialog.FileName} ({_container.Algorithm} / {_container.HashAlgorithm} / {_container.FileSystemType})";
            }
            catch (Exception ex)
            {
                OpenMenuItem.IsEnabled = true;
                MessageBox.Show(this, ex.Message, "Unable to open container", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseMenuItem_Click(object sender, RoutedEventArgs e)
        {
            _container?.Close();
            _container = null;

            ContainerTreeView.ItemsSource = null;
            ClearContentPane();

            OpenMenuItem.IsEnabled = true;
            CloseMenuItem.IsEnabled = false;
            StatusText.Text = "No container open.";
        }

        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async System.Threading.Tasks.Task LoadRootAsync()
        {
            var entries = await _container!.Root.GetEntriesAsync();
            var nodes = entries
                .OrderBy(e => e is IFile)
                .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .Select(e => new EntryNode(e));

            ContainerTreeView.ItemsSource = new ObservableCollection<EntryNode>(nodes);
        }

        private async void ContainerTreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue is not EntryNode { IsDirectory: false, File: not null } node)
            {
                return;
            }

            await DisplayFileAsync(node.File!);
        }

        private async System.Threading.Tasks.Task DisplayFileAsync(IFile file)
        {
            ClearContentPane();
            try
            {
                switch (Path.GetExtension(file.Name).ToLowerInvariant())
                {
                    case ".jpg":
                    case ".jpeg":
                    case ".png":
                        var imageBytes = await file.ReadAllBytesAsync();
                        ContentImage.Source = LoadBitmap(imageBytes);
                        ContentImage.Visibility = Visibility.Visible;
                        break;

                    case ".txt":
                        ContentText.Text = await file.ReadAllTextAsync();
                        ContentText.Visibility = Visibility.Visible;
                        break;

                    default:
                        var bytes = await file.ReadAllBytesAsync();
                        ContentText.Text = BuildHexDump(bytes);
                        ContentText.Visibility = Visibility.Visible;
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to read file", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearContentPane()
        {
            ContentImage.Source = null;
            ContentImage.Visibility = Visibility.Collapsed;
            ContentText.Text = string.Empty;
            ContentText.Visibility = Visibility.Collapsed;
        }

        private static BitmapImage LoadBitmap(byte[] bytes)
        {
            using var stream = new MemoryStream(bytes);
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad;
            bitmap.StreamSource = stream;
            bitmap.EndInit();
            bitmap.Freeze();
            return bitmap;
        }

        private static string BuildHexDump(byte[] data)
        {
            const int bytesPerLine = 16;
            var sb = new StringBuilder();

            for (var offset = 0; offset < data.Length; offset += bytesPerLine)
            {
                var count = Math.Min(bytesPerLine, data.Length - offset);

                sb.Append(offset.ToString("X8")).Append("  ");
                for (var i = 0; i < bytesPerLine; i++)
                {
                    sb.Append(i < count ? data[offset + i].ToString("X2") : "  ").Append(' ');
                    if (i == 7)
                    {
                        sb.Append(' ');
                    }
                }

                sb.Append(' ');
                for (var i = 0; i < count; i++)
                {
                    var b = data[offset + i];
                    sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
