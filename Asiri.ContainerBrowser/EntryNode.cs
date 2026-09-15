using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
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
        private string _name;
        private bool _isExpanded;
        private bool _childrenLoaded;

        /// <param name="displayName">
        /// Overrides <paramref name="entry"/>'s own <see cref="IFileSystemEntry.Name"/> for display -
        /// used only for the container's root, whose real name is the empty string.
        /// </param>
        public EntryNode(IFileSystemEntry entry, EntryNode? parentNode = null, bool isRoot = false, string? displayName = null)
        {
            _entry = entry;
            ParentNode = parentNode;
            IsRoot = isRoot;
            _name = displayName ?? entry.Name;
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
            _name = "Loading...";
            IconUri = OtherFileIcon;
            Children = new ObservableCollection<EntryNode>();
            IsPlaceholder = true;
        }

        public string Name
        {
            get => _name;
            private set
            {
                _name = value;
                OnPropertyChanged();
            }
        }

        public Uri IconUri { get; }

        public bool IsDirectory => _entry is IDirectory;

        /// <summary>
        /// True only for the single node representing the container's root, which the tree shows as
        /// an ordinary (always-present) node rather than showing its children as bare top-level items.
        /// Root gets its own, more restricted context menu - see <see cref="MainWindow"/> - since
        /// renaming, deleting, or moving it makes no sense (and the underlying <c>RenameAsync</c>/
        /// <c>MoveToAsync</c> throw for it).
        /// </summary>
        public bool IsRoot { get; }

        /// <summary>
        /// The wrapped entry, for the operations - rename, move, attributes, timestamps - defined on
        /// <see cref="IFileSystemEntry"/> itself and so applicable uniformly to files and directories.
        /// Never null for a real (non-placeholder) node.
        /// </summary>
        public IFileSystemEntry Entry => _entry;

        public IFile? File => _entry as IFile;

        public IDirectory? Directory => _entry as IDirectory;

        public bool IsPlaceholder { get; }

        public ObservableCollection<EntryNode> Children { get; }

        /// <summary>
        /// The node whose <see cref="Children"/> this node currently lives in. Null only for the
        /// single root node itself (see <see cref="IsRoot"/>), which has no parent and is never
        /// detached/reattached - every other node always has a real one, even a node directly under
        /// the container's root.
        /// </summary>
        public EntryNode? ParentNode { get; set; }

        /// <summary>
        /// Whether this directory node's <see cref="Children"/> reflect the container's actual
        /// contents. False until the node has been expanded at least once (see <see cref="IsExpanded"/>).
        /// Callers that create a new child under this node should skip adding it here while false -
        /// the real listing will pick it up naturally the first time this node is expanded.
        /// </summary>
        public bool ChildrenLoaded => _childrenLoaded;

        /// <summary>
        /// Renames this node in place, preserving its identity (selection, expansion state) - the
        /// caller is responsible for re-sorting it within its sibling collection via
        /// <see cref="InsertSorted"/> if the new name changes its sort position.
        /// </summary>
        public void UpdateName(string newName)
        {
            Name = newName;
        }

        /// <summary>
        /// Adds a node to this directory's <see cref="Children"/> in sorted order, unless its
        /// children haven't been loaded yet (see <see cref="ChildrenLoaded"/>), in which case there
        /// is nothing to add to - the node will appear on its own the first time this one is expanded.
        /// </summary>
        public void AddChild(EntryNode node)
        {
            if (_childrenLoaded)
            {
                InsertSorted(Children, node);
            }
        }

        /// <summary>
        /// Marks a directory node as having no real children to load - for a directory this app just
        /// created itself, which is known to be empty, rather than treating it as unexpanded (which
        /// would silently drop anything added to it - e.g. a file moved straight into it before it's
        /// ever been expanded - since <see cref="AddChild"/> only inserts once <see cref="ChildrenLoaded"/>
        /// is true). Clears the loading placeholder, since there is nothing left to load.
        /// </summary>
        public void MarkAsKnownEmpty()
        {
            _childrenLoaded = true;
            Children.Clear();
        }

        /// <summary>
        /// Removes a node from this directory's <see cref="Children"/>, if present.
        /// </summary>
        public void RemoveChild(EntryNode node)
        {
            Children.Remove(node);
        }

        /// <summary>
        /// Inserts <paramref name="node"/> into <paramref name="collection"/> at the position that
        /// keeps it sorted the way this tree has always sorted entries: directories before files,
        /// then by name, ordinal-ignorecase. The one place that ordering rule lives.
        /// </summary>
        public static void InsertSorted(ObservableCollection<EntryNode> collection, EntryNode node)
        {
            var index = 0;
            while (index < collection.Count && CompareOrder(collection[index], node) <= 0)
            {
                index++;
            }
            collection.Insert(index, node);
        }

        private static int CompareOrder(EntryNode a, EntryNode b)
        {
            if (a.IsDirectory != b.IsDirectory)
            {
                return a.IsDirectory ? -1 : 1;
            }
            return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        }

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

        /// <summary>
        /// Loads this directory's children from the container. Normally triggered lazily by
        /// <see cref="IsExpanded"/>, but exposed so <see cref="MainWindow"/> can load the root node's
        /// children eagerly at open time (matching the app's previous behaviour, before root itself
        /// became a node) rather than requiring an extra click to expand it.
        /// </summary>
        internal async System.Threading.Tasks.Task LoadChildrenAsync()
        {
            _childrenLoaded = true;
            try
            {
                var entries = await Directory!.GetEntriesAsync();

                Children.Clear();
                foreach (var entry in entries)
                {
                    InsertSorted(Children, new EntryNode(entry, this));
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
