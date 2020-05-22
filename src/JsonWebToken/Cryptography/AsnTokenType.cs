namespace JsonWebToken.Cryptography
{
    internal enum AsnTokenType
    {
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        Sequence = 16,

        Undefined = -1,
    }
}
