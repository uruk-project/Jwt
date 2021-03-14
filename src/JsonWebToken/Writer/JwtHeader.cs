namespace JsonWebToken
{
    /// <summary>Represents the metadata of the JWT, like the cryptographic 
    /// operations applied to the JWT and optionally any additional properties of the JWT.</summary>
    public sealed class JwtHeader : JsonObject
    {
        /// <summary>Initializes a new instance of the <see cref="JsonObject"/> class.</summary>
        public JwtHeader()
            : base(MemberStore.CreateSlowGrowingStore())
        {
        }
    }
}