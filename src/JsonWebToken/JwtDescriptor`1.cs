namespace JsonWebToken
{
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor
    {
        public TPayload Payload { get; set; }
    }
}
