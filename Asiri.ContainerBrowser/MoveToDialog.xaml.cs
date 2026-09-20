using System.Windows;
using System.Windows.Controls;

namespace uk.andyjohnson.Asiri.ContainerBrowser
{
    /// <summary>
    /// Modal directory picker for the "Move to..." command. Reuses the caller's own live
    /// <see cref="EntryNode"/> tree (<paramref name="rootNode"/>, via the constructor) rather than
    /// rebuilding a separate one, so lazy loading (<see cref="EntryNode.IsExpanded"/> triggering a
    /// load) works exactly as it does in the main window, and the destination the user picks is the
    /// very same node <see cref="MainWindow"/> would otherwise have to look up separately. Files are
    /// hidden - not removed - since only a directory can be a destination, and the node being moved
    /// is disabled so it can't be picked as its own destination. The root node itself is shown and
    /// selectable like any other directory, so moving something to the top level is just picking it.
    /// Moving a directory into one of its own descendants isn't pre-emptively blocked here; it's
    /// simpler and consistent with this app's existing convention to let <c>MoveToAsync</c> reject
    /// that and report the resulting error.
    /// </summary>
    public partial class MoveToDialog : Window
    {
        private readonly EntryNode _movingNode;

        internal MoveToDialog(EntryNode rootNode, EntryNode movingNode)
        {
            InitializeComponent();
            _movingNode = movingNode;
            DestinationTreeView.ItemsSource = new[] { rootNode };
        }

        internal EntryNode? SelectedNode { get; private set; }

        private void TreeViewItem_Loaded(object sender, RoutedEventArgs e)
        {
            var item = (TreeViewItem)sender;
            if (ReferenceEquals(item.DataContext, _movingNode))
            {
                item.IsEnabled = false;
            }
        }

        private void DestinationTreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            OkButton.IsEnabled = e.NewValue is EntryNode { IsDirectory: true, IsPlaceholder: false };
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedNode = (EntryNode)DestinationTreeView.SelectedItem;
            DialogResult = true;
        }
    }
}
