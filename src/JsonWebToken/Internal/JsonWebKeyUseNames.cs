namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebKeyUse (sec 4.2)
    /// http://tools.ietf.org/html/rfc7517#section-4
    /// </summary>
    public static class JsonWebKeyUseNames
    {
        public const string Sig = "sig";
        public const string Enc = "enc";
    }
}
