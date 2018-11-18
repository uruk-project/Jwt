namespace JsonWebToken
{
    public interface IAlgorithm
    {
        sbyte Id { get; }
        string Name { get; }
    }
}