using System.IO;
using System.Threading;
using GeneralZip.Abstractions;

namespace GeneralZip.Internal;

internal interface ICancellableEntryStreamProvider
{
    Stream OpenEntryStream(IArchiveEntry entry, CancellationToken cancellationToken);
}
