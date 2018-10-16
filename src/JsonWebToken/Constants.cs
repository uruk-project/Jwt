namespace JsonWebToken
{
    internal static class Constants
    {
        internal const int JweSegmentCount = 5;

        internal const int JwsSegmentCount = 3;

        internal const int MaxStackallocBytes = 1024 * 1024;

        internal static readonly int DecompressionBufferLength = 1024;
    }
}
