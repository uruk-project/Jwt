namespace JsonWebToken.Performance
{
    public class EncodingWrapper
    {
        public EncodingWrapper(byte[] source, byte[] destination, int count)
        {
            Source = source;
            Destination = destination;
            Count = count;
        }

        public byte[] Source { get; }
        public byte[] Destination { get; }
        public int Count { get; }

        public override string ToString()
        {
            return Count.ToString();
        }
    }
}
