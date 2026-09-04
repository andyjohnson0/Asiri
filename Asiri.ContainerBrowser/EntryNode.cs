using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Wraps a single <see cref="IFileSystemEntry"/> for display in the container tree. Directory
    /// nodes load their children lazily, the first time they are expanded, rather than the whole
    /// tree being loaded up front.
    /// </summary>
    internal sealed class EntryNode : INotifyPropertyChanged
    {
        private static readonly Uri FolderIcon = new("Icons/folder-fill.svg", UriKind.Relative);
        private static readonly Uri ImageFileIcon = new("Icons/file-earmark-image-fill.svg", UriKind.Relative);
        private static readonly Uri TextFileIcon = new("Icons/file-earmark-text-fill.svg", UriKind.Relative);
        private static readonly Uri OtherFileIcon = new("Icons/file-earmark-binary-fill.svg", UriKind.Relative);

        private readonly IFileSystemEntry _entry;
        private bool _isExpanded;
        private bool _childrenLoaded;

        public EntryNode(IFileSystemEntry entry)
        {
            _entry = entry;
            Name = entry.Name;
            IconUri = ChooseIcon(entry);
            Children = new ObservableCollection<EntryNode>();
            if (entry is IDirectory)
            {
                // A placeholder so the TreeViewItem shows an expander before its real children -
                // which require an async call to load - are known.
                Children.Add(new EntryNode());
            }
        }

        // Placeholder-only constructor: never bound to a real entry, never itself expandable.
        private EntryNode()
        {
            _entry = null!;
            Name = "Loading...";
            IconUri = OtherFileIcon;
            Children = new ObservableCollection<EntryNode>();
            IsPlaceholder = true;
        }

        public string Name { get; }

        public Uri IconUri { get; }

        public bool IsDirectory => _entry is IDirectory;

        public IFile? File => _entry as IFile;

        public IDirectory? Directory => _entry as IDirectory;

        public bool IsPlaceholder { get; }

        public ObservableCollection<EntryNode> Children { get; }

        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded == value)
                {
                    return;
                }
                _isExpanded = value;
                OnPropertyChanged();

                if (value && !_childrenLoaded && Directory != null)
                {
                    _ = LoadChildrenAsync();
                }
            }
        }

        private async System.Threading.Tasks.Task LoadChildrenAsync()
        {
            _childrenLoaded = true;
            try
            {
                var entries = await Directory!.GetEntriesAsync();
                var nodes = entries
                    .OrderBy(e => e is IFile)
                    .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(e => new EntryNode(e));

                Children.Clear();
                foreach (var node in nodes)
                {
                    Children.Add(node);
                }
            }
            catch (Exception ex)
            {
                Children.Clear();
                MessageBox.Show(Application.Current.MainWindow, ex.Message, "Unable to read directory",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static Uri ChooseIcon(IFileSystemEntry entry)
        {
            if (entry is IDirectory)
            {
                return FolderIcon;
            }

            return Path.GetExtension(entry.Name).ToLowerInvariant() switch
            {
                ".jpg" or ".jpeg" or ".png" => ImageFileIcon,
                ".txt" => TextFileIcon,
                _ => OtherFileIcon
            };
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
