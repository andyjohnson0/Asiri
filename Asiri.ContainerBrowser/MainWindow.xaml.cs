using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
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
        private ContainerAccessMode _accessMode;
        private EntryNode? _rootNode;

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

            using var cancellationTokenSource = new CancellationTokenSource();
            var progressDialog = new ProgressDialog(cancellationTokenSource, "Opening container...") { Owner = this };
            progressDialog.Show();
            IsEnabled = false;

            try
            {
                _accessMode = credentialsDialog.AccessMode;
                _container = await VeraCryptContainer.OpenAsync(
                    new FileInfo(openDialog.FileName), credentialsDialog.Password, credentialsDialog.Pim, credentialsDialog.KeyFiles,
                    credentialsDialog.Algorithm, credentialsDialog.HashAlgorithm, accessMode: _accessMode, cancellationToken: cancellationTokenSource.Token);

                ClearContentPane();
                await LoadRootAsync(Path.GetFileName(openDialog.FileName));

                CloseMenuItem.IsEnabled = true;
                WritingEnabledMenuItem.IsEnabled = _accessMode == ContainerAccessMode.ReadWrite;
                UpdateWriteStatusText();
                StatusText.Text = $"Opened: {openDialog.FileName} ({_container.Algorithm} / {_container.HashAlgorithm} / {_container.FileSystemType})";
            }
            catch (OperationCanceledException)
            {
                OpenMenuItem.IsEnabled = true;
                StatusText.Text = "Open cancelled.";
            }
            catch (Exception ex)
            {
                OpenMenuItem.IsEnabled = true;
                MessageBox.Show(this, ex.Message, "Unable to open container", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsEnabled = true;
                progressDialog.Close();
            }
        }

        private void CloseMenuItem_Click(object sender, RoutedEventArgs e)
        {
            _container?.Close();
            _container = null;
            _rootNode = null;

            ContainerTreeView.ItemsSource = null;
            ClearContentPane();

            OpenMenuItem.IsEnabled = true;
            CloseMenuItem.IsEnabled = false;
            WritingEnabledMenuItem.IsEnabled = false;
            WritingEnabledMenuItem.IsChecked = false;
            StatusText.Text = "No container open.";
            WriteStatusText.Text = string.Empty;
        }

        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        /// <summary>
        /// Changes a container's password, keyfiles, PIM, and/or hash algorithm via
        /// <see cref="VeraCryptContainer.ChangePasswordAsync"/> - a standalone operation on the file
        /// the user picks, not on whatever container (if any) is currently open in this window: that
        /// method is static and never touches the filesystem region, so it never needs one open. If
        /// the same file IS currently open elsewhere, the attempt fails cleanly with a sharing
        /// violation (wrapped in a descriptive message by ChangePasswordAsync itself) rather than
        /// this window pre-emptively guessing whether that's the case.
        /// </summary>
        private async void ChangePasswordMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Title = "Change Container Password",
                Filter = "VeraCrypt containers (*.hc)|*.hc|All files (*.*)|*.*"
            };
            if (openDialog.ShowDialog(this) != true)
            {
                return;
            }

            // requireAlgorithmAndHash: true - ChangePasswordAsync has no auto-detecting overload, so
            // both must be known and explicitly chosen here, unlike the ordinary Open flow.
            var oldCredentialsDialog = new CredentialsDialog(requireAlgorithmAndHash: true) { Owner = this };
            if (oldCredentialsDialog.ShowDialog() != true)
            {
                return;
            }

            var newCredentialsDialog = new NewPasswordDialog { Owner = this };
            if (newCredentialsDialog.ShowDialog() != true)
            {
                return;
            }

            using var cancellationTokenSource = new CancellationTokenSource();
            var progressDialog = new ProgressDialog(cancellationTokenSource, "Changing password...") { Owner = this };
            progressDialog.Show();
            IsEnabled = false;

            try
            {
                await VeraCryptContainer.ChangePasswordAsync(
                    new FileInfo(openDialog.FileName),
                    oldCredentialsDialog.Password, oldCredentialsDialog.Algorithm!.Value, oldCredentialsDialog.HashAlgorithm!.Value,
                    oldCredentialsDialog.Pim, oldCredentialsDialog.KeyFiles,
                    newCredentialsDialog.NewPassword, newCredentialsDialog.NewPim, newCredentialsDialog.NewKeyFiles, newCredentialsDialog.NewHashAlgorithm,
                    cancellationTokenSource.Token);

                MessageBox.Show(this, "The container's password has been changed.", "Change Password", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Change password cancelled.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to change password", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsEnabled = true;
                progressDialog.Close();
            }
        }

        private void WritingEnabledMenuItem_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _container!.IsWritable = WritingEnabledMenuItem.IsChecked;
            }
            catch (Exception ex)
            {
                WritingEnabledMenuItem.IsChecked = _container!.IsWritable;
                MessageBox.Show(this, ex.Message, "Unable to change writing state", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            UpdateWriteStatusText();
        }

        private void UpdateWriteStatusText()
        {
            WriteStatusText.Text = _container == null
                ? string.Empty
                : _container.IsWritable ? "Writing enabled" : _accessMode == ContainerAccessMode.ReadWrite ? "Writing disabled" : "Read-only";
        }

        /// <summary>
        /// Builds the single root node representing the container's root directory - the tree shows
        /// it as an ordinary node (always present, always expanded) rather than showing its children
        /// as bare top-level items, so there's a real destination to move something to "the top" and
        /// a real row to drop onto for that. Its children are loaded eagerly, matching how the app
        /// behaved before root itself became a node, rather than requiring an extra click to expand it.
        /// </summary>
        private async System.Threading.Tasks.Task LoadRootAsync(string containerFileName)
        {
            _rootNode = new EntryNode(_container!.Root, isRoot: true, displayName: containerFileName);
            await _rootNode.LoadChildrenAsync();
            _rootNode.IsExpanded = true;

            ContainerTreeView.ItemsSource = new[] { _rootNode };
        }

        /// <summary>
        /// Removes <paramref name="node"/> from its parent's <see cref="EntryNode.Children"/>. Pairs
        /// with <see cref="AttachNode"/>; used directly (with a rename in between, since renaming can
        /// change sort position) and via <see cref="RelocateNode"/> (for a move). Never called for the
        /// root node itself, which has no parent and can't be renamed or moved.
        /// </summary>
        private static void DetachNode(EntryNode node)
        {
            node.ParentNode!.RemoveChild(node);
        }

        /// <summary>
        /// Adds <paramref name="node"/> into <paramref name="parent"/>'s <see cref="EntryNode.Children"/>
        /// in sorted order. <paramref name="parent"/> may be the root node itself.
        /// </summary>
        private static void AttachNode(EntryNode node, EntryNode parent)
        {
            node.ParentNode = parent;
            parent.AddChild(node);
        }

        /// <summary>
        /// Moves <paramref name="node"/> to <paramref name="newParent"/> after a successful
        /// <see cref="IFileSystemEntry.MoveToAsync"/>, whether driven by the "Move to..." menu command
        /// or by drag-and-drop. <paramref name="newParent"/> may be the root node itself.
        /// </summary>
        private static void RelocateNode(EntryNode node, EntryNode newParent)
        {
            DetachNode(node);
            AttachNode(node, newParent);
        }

        private EntryNode? _contextNode;

        /// <summary>
        /// Records which node's row was actually right-clicked, via the same hit-testing
        /// <see cref="FindTreeViewItem"/> already uses for drag-and-drop, rather than relying on a
        /// shared <see cref="ContextMenu"/> instance's own <c>PlacementTarget.DataContext</c> binding
        /// - the previous approach, which turned out not to reliably reflect the actual row clicked
        /// (confirmed by a real repro: choosing "Move to..." from a file's own context menu ended up
        /// calling <c>MoveToAsync</c> on the container's root instead of that file). Every command
        /// handler reads <see cref="_contextNode"/> instead of the sender's DataContext.
        /// </summary>
        private void ContainerTreeView_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            _contextNode = FindTreeViewItem(e.OriginalSource as DependencyObject)?.DataContext as EntryNode;
        }

        private EntryNode GetContextNode(object sender) => _contextNode!;

        private Point _dragStartPoint;
        private bool _dragInProgress;

        private void TreeViewItem_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dragStartPoint = e.GetPosition(null);
        }

        /// <summary>
        /// Starts a drag once the mouse has moved far enough with the button held. A directory node
        /// can only be dragged to move it within the container, which needs writing armed. A file
        /// node can always be dragged - regardless of whether writing is armed - since dragging it
        /// out to another application (Explorer, say) to export a copy doesn't touch the container at
        /// all; only dropping it back inside our own tree as a move does, and that drop is re-checked
        /// against <see cref="VeraCryptContainer.IsWritable"/> independently in <see cref="GetDropTargetNode"/>.
        /// </summary>
        /// <remarks>
        /// PreviewMouseMove tunnels: for a mouse over a nested item, this fires first on every
        /// ancestor TreeViewItem (root, then any intermediate directory) - since the EventSetter that
        /// wires this up is on the shared <c>TreeViewItem</c> style, not one specific instance -
        /// before it ever reaches the item actually under the cursor. Without the check below, that
        /// ancestor would win the race to call <see cref="DragDrop.DoDragDrop"/> and become the drag
        /// source instead - a real, confirmed bug: dragging a nested file this way actually dragged
        /// the container's root. <paramref name="sender"/> only proceeds once it's confirmed to BE the
        /// item <see cref="MouseEventArgs.OriginalSource"/> was actually hit-tested against, which -
        /// unlike <c>sender</c> - doesn't change as the event tunnels down.
        /// </remarks>
        private async void TreeViewItem_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (_dragInProgress || e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            if (!ReferenceEquals(FindTreeViewItem(e.OriginalSource as DependencyObject), sender))
            {
                return;
            }

            var current = e.GetPosition(null);
            if (Math.Abs(current.X - _dragStartPoint.X) < SystemParameters.MinimumHorizontalDragDistance &&
                Math.Abs(current.Y - _dragStartPoint.Y) < SystemParameters.MinimumVerticalDragDistance)
            {
                return;
            }

            if (sender is not TreeViewItem { DataContext: EntryNode { IsPlaceholder: false } node } item)
            {
                return;
            }

            if (node.IsDirectory && _container?.IsWritable != true)
            {
                return;
            }

            _dragInProgress = true;
            try
            {
                var data = new DataObject();
                data.SetData(typeof(EntryNode), node);

                // DoDragDrop needs its data ready up front - WPF has no lazy/delay-rendered drag data
                // without implementing a custom COM IDataObject - so a file being dragged is exported
                // to a temporary copy eagerly, before the OS drag even begins, whether or not the drop
                // ends up being an external export or an internal move. That's an accepted latency
                // cost (proportional to the file's size) in exchange for not needing that complexity.
                if (node.File is { } file)
                {
                    var exportPath = await TryExportToTempFileAsync(file);
                    if (exportPath != null)
                    {
                        data.SetData(DataFormats.FileDrop, new[] { exportPath });
                    }
                }

                DragDrop.DoDragDrop(item, data, DragDropEffects.Move | DragDropEffects.Copy);
            }
            finally
            {
                _dragInProgress = false;
            }
        }

        /// <summary>
        /// Decrypts <paramref name="file"/> into a freshly created temp directory (never reusing or
        /// overwriting a previous export, so a concurrent read by whatever the previous drag was
        /// dropped onto can never be disturbed) so it can be handed to another application as real
        /// <see cref="DataFormats.FileDrop"/> data. The exported copy is intentionally left behind in
        /// the temp folder rather than deleted right after the drop - the receiving application may
        /// still be reading it after <see cref="DragDrop.DoDragDrop"/> returns, particularly for a
        /// large file - and is cleaned up the normal way any temp file is, rather than by this app.
        /// </summary>
        private async System.Threading.Tasks.Task<string?> TryExportToTempFileAsync(IFile file)
        {
            try
            {
                var tempDirectory = Path.Combine(Path.GetTempPath(), "Asiri.ContainerBrowser", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tempDirectory);
                var tempPath = Path.Combine(tempDirectory, file.Name);

                var bytes = await file.ReadAllBytesAsync();
                await System.IO.File.WriteAllBytesAsync(tempPath, bytes);
                return tempPath;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to prepare file for dragging out", MessageBoxButton.OK, MessageBoxImage.Error);
                return null;
            }
        }

        private static TreeViewItem? FindTreeViewItem(DependencyObject? source)
        {
            while (source != null && source is not TreeViewItem)
            {
                source = VisualTreeHelper.GetParent(source);
            }
            return source as TreeViewItem;
        }

        /// <summary>
        /// Finds the directory node under the drag cursor, if the drag can legally be dropped there:
        /// writing must be armed, the target must be a directory (which the root node also is, so
        /// dropping onto it targets the container's root, same as any other directory), and - for an
        /// internal (tree item) drag - the target can't be the item itself. Landing on the tree's
        /// empty background - below every row, where there's no <see cref="TreeViewItem"/> to
        /// hit-test - falls back to the root node too, rather than being rejected, since root's own
        /// row is a thin target compared to the whole area its (always-expanded) children occupy.
        /// Shared by <c>DragOver</c> (to choose the cursor effect) and <c>Drop</c> (to act on it), so
        /// the two can never disagree.
        /// </summary>
        private EntryNode? GetDropTargetNode(DragEventArgs e)
        {
            if (_container?.IsWritable != true || _rootNode == null)
            {
                return null;
            }

            var hitItem = FindTreeViewItem(e.OriginalSource as DependencyObject);
            if ((hitItem == null ? _rootNode : hitItem.DataContext as EntryNode) is not { IsDirectory: true } node)
            {
                return null;
            }

            var isFileDrop = e.Data.GetDataPresent(DataFormats.FileDrop);
            var isInternalDrag = e.Data.GetDataPresent(typeof(EntryNode));
            if (!isFileDrop && !isInternalDrag)
            {
                return null;
            }

            if (isInternalDrag && e.Data.GetData(typeof(EntryNode)) is EntryNode source && ReferenceEquals(source, node))
            {
                return null;
            }

            return node;
        }

        private void ContainerTreeView_DragOver(object sender, DragEventArgs e)
        {
            var target = GetDropTargetNode(e);
            e.Effects = target == null ? DragDropEffects.None : e.Data.GetDataPresent(typeof(EntryNode)) ? DragDropEffects.Move : DragDropEffects.Copy;
            e.Handled = true;
        }

        private async void ContainerTreeView_Drop(object sender, DragEventArgs e)
        {
            e.Handled = true;
            var targetNode = GetDropTargetNode(e);
            if (targetNode?.Directory == null)
            {
                return;
            }

            // An internal drag of a file also carries FileDrop data now (for dragging it out to
            // another application), so typeof(EntryNode) - which only an internal drag ever carries -
            // is checked first: dropped back onto our own tree, it's always a move, never a duplicate
            // import of the temp copy that drag also happens to be carrying.
            if (e.Data.GetDataPresent(typeof(EntryNode)) && e.Data.GetData(typeof(EntryNode)) is EntryNode sourceNode)
            {
                try
                {
                    await sourceNode.Entry.MoveToAsync(targetNode.Directory);
                    RelocateNode(sourceNode, targetNode);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Unable to move", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var paths = (string[])e.Data.GetData(DataFormats.FileDrop)!;
                await ImportFilesAsync(targetNode.Directory, targetNode, paths);
            }
        }

        /// <summary>
        /// Disabling a <see cref="MenuItem"/> is fine while its popup is open, but disabling the
        /// <see cref="ContextMenu"/> itself here previously caused it to immediately close (and, on
        /// the next open, get stuck unable to dismiss) - so each command is disabled individually
        /// instead, leaving the ContextMenu's own open/close lifecycle undisturbed.
        /// </summary>
        /// <remarks>
        /// Which rule applies to a given item is read off its own <c>Tag</c> ("Paste" or
        /// "Properties" - see the XAML - anything else, including no tag at all, gets the default
        /// rule). This replaced an earlier, broken attempt at singling those two out via
        /// <c>ContextMenu.FindName</c>: <c>x:Name</c> on an element declared inside
        /// <c>Window.Resources</c> is never registered in any runtime <c>NameScope</c> unless one is
        /// set up explicitly, so every call to <c>FindName</c> there was silently returning null and
        /// quietly no-oping - Paste always ended up just mirroring the general writable/not-writable
        /// state (rather than also checking the clipboard), and Properties never got re-enabled at
        /// all. <c>menu.Items</c> itself needs no such workaround: enumerating it is how the general
        /// per-item disabling below already worked correctly throughout.
        /// </remarks>
        private void DirectoryContextMenu_Opened(object sender, RoutedEventArgs e) => SetContextMenuItemsEnabled((ContextMenu)sender);

        private void FileContextMenu_Opened(object sender, RoutedEventArgs e) => SetContextMenuItemsEnabled((ContextMenu)sender);

        private void RootContextMenu_Opened(object sender, RoutedEventArgs e) => SetContextMenuItemsEnabled((ContextMenu)sender);

        private void SetContextMenuItemsEnabled(ContextMenu menu)
        {
            var writable = _container?.IsWritable == true;
            foreach (var menuItem in menu.Items.OfType<MenuItem>())
            {
                menuItem.IsEnabled = menuItem.Tag switch
                {
                    "Properties" => true,
                    "Paste" => writable && Clipboard.ContainsFileDropList(),
                    _ => writable
                };
            }
        }

        /// <summary>
        /// Adds a newly created or imported entry into the tree under <paramref name="parentNode"/>
        /// (which may be the root node itself), the same way <see cref="RelocateNode"/> attaches a
        /// moved one - so every place a node enters the visible tree goes through the one
        /// <see cref="AttachNode"/> path. A freshly created directory is marked as known-empty (see
        /// <see cref="EntryNode.MarkAsKnownEmpty"/>) rather than left "unexpanded", since otherwise
        /// anything added into it immediately afterwards - e.g. a file dragged straight into a
        /// subdirectory just created via the context menu - would silently be dropped by
        /// <see cref="EntryNode.AddChild"/>.
        /// </summary>
        private EntryNode AddNewChildNode(IFileSystemEntry createdEntry, EntryNode parentNode)
        {
            var node = new EntryNode(createdEntry);
            if (createdEntry is IDirectory)
            {
                node.MarkAsKnownEmpty();
            }
            AttachNode(node, parentNode);
            return node;
        }

        private async void NewSubdirectory_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            var dialog = new TextInputDialog("New Subdirectory", "Subdirectory name:") { Owner = this };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            try
            {
                var created = await node.Directory!.CreateDirectoryAsync(dialog.Value);
                AddNewChildNode(created, node);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to create subdirectory", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void NewFile_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            var dialog = new TextInputDialog("New File", "File name:") { Owner = this };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            try
            {
                var created = await node.Directory!.CreateFileAsync(dialog.Value);
                AddNewChildNode(created, node);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to create file", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void Rename_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            var dialog = new TextInputDialog("Rename", "New name:", node.Name) { Owner = this };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            try
            {
                await node.Entry.RenameAsync(dialog.Value);
                DetachNode(node);
                node.UpdateName(dialog.Value);
                // Never the root node here - it has no Rename command - so ParentNode is never null.
                AttachNode(node, node.ParentNode!);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to rename", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void Delete_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            if (MessageBox.Show(this, $"Delete '{node.Name}'?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            try
            {
                if (node.IsDirectory)
                {
                    try
                    {
                        await node.Directory!.DeleteAsync(recursive: false);
                    }
                    catch (IOException)
                    {
                        if (MessageBox.Show(this, $"'{node.Name}' is not empty. Delete it and everything in it?",
                                "Confirm Recursive Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                        {
                            return;
                        }
                        await node.Directory!.DeleteAsync(recursive: true);
                    }
                }
                else
                {
                    await node.File!.DeleteAsync();
                }

                DetachNode(node);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to delete", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void MoveTo_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            if (_rootNode == null)
            {
                return;
            }

            var dialog = new MoveToDialog(_rootNode, node) { Owner = this };
            if (dialog.ShowDialog() != true || dialog.SelectedNode?.Directory == null)
            {
                return;
            }

            try
            {
                await node.Entry.MoveToAsync(dialog.SelectedNode.Directory);
                RelocateNode(node, dialog.SelectedNode);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to move", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void Paste_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            if (!Clipboard.ContainsFileDropList())
            {
                return;
            }

            await ImportFilesAsync(node.Directory!, node, Clipboard.GetFileDropList().Cast<string>());
        }

        /// <summary>
        /// Imports each of <paramref name="paths"/> as a new file into <paramref name="target"/>
        /// (<paramref name="targetNode"/> may be the root node itself), used by both clipboard paste
        /// and external drag-and-drop. Importing whole directories isn't supported - any path that is
        /// itself a directory is silently skipped - so this only ever creates files. On a name
        /// collision, asks once per file whether to replace it; declining skips just that file and the
        /// rest of the batch continues.
        /// </summary>
        private async System.Threading.Tasks.Task ImportFilesAsync(IDirectory target, EntryNode targetNode, IEnumerable<string> paths)
        {
            var filePaths = paths.Where(p => !Directory.Exists(p)).ToList();
            if (filePaths.Count == 0)
            {
                return;
            }

            using var cancellationTokenSource = new CancellationTokenSource();
            var progressDialog = new ProgressDialog(cancellationTokenSource, "Importing files...") { Owner = this };
            progressDialog.Show();
            IsEnabled = false;

            try
            {
                var token = cancellationTokenSource.Token;
                var existingEntries = (await target.GetEntriesAsync(token)).ToDictionary(en => en.Name, en => en, StringComparer.OrdinalIgnoreCase);

                foreach (var path in filePaths)
                {
                    token.ThrowIfCancellationRequested();
                    var name = Path.GetFileName(path);

                    if (existingEntries.TryGetValue(name, out var existing))
                    {
                        if (existing is not IFile existingFile)
                        {
                            MessageBox.Show(this, $"'{name}' is a directory here; it can't be replaced by a file.",
                                "Unable to import", MessageBoxButton.OK, MessageBoxImage.Error);
                            continue;
                        }

                        if (MessageBox.Show(this, $"'{name}' already exists in this directory. Replace it?",
                                "Confirm Replace", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                        {
                            continue;
                        }

                        await existingFile.DeleteAsync(token);
                        existingEntries.Remove(name);
                    }

                    using var sourceStream = File.OpenRead(path);
                    var created = await target.CreateFileAsync(name, sourceStream, token);
                    AddNewChildNode(created, targetNode);
                    existingEntries[name] = created;
                }
            }
            catch (OperationCanceledException)
            {
                // Already-imported files stay imported; the rest of the batch is simply not attempted.
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to import files", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsEnabled = true;
                progressDialog.Close();
            }
        }

        /// <summary>
        /// Viewing properties is always available, regardless of whether writing is armed - it's a
        /// read, not a mutation - so <see cref="EntryPropertiesDialog"/> is opened read-only (no
        /// editable fields, no attempt to save) whenever it isn't. The decision is made here, from
        /// the actual current <see cref="VeraCryptContainer.IsWritable"/> state, rather than trusted
        /// to whatever the context menu happened to show at the time it was opened.
        /// </summary>
        private async void EditProperties_Click(object sender, RoutedEventArgs e)
        {
            var node = GetContextNode(sender);
            var readOnly = _container?.IsWritable != true;
            try
            {
                var attributes = await node.Entry.GetAttributesAsync();
                var creationTimeUtc = await node.Entry.GetCreationTimeUtcAsync();
                var lastWriteTimeUtc = await node.Entry.GetLastWriteTimeUtcAsync();

                var dialog = new EntryPropertiesDialog(node.Name, attributes, creationTimeUtc, lastWriteTimeUtc, readOnly) { Owner = this };
                if (dialog.ShowDialog() != true || readOnly)
                {
                    return;
                }

                await node.Entry.SetAttributesAsync(dialog.ResultAttributes);
                await node.Entry.SetCreationTimeUtcAsync(dialog.ResultCreationTimeUtc);
                await node.Entry.SetLastWriteTimeUtcAsync(dialog.ResultLastWriteTimeUtc);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Unable to edit properties", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
