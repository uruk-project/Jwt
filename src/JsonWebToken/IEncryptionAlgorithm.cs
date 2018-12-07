namespace JsonWebToken
{
    /// <summary>
    /// Represents a cryprographic algorithm used in the 'alg' or 'enc' header parameters.
    /// </summary>
    public interface IAlgorithm
    {
        /// <summary>
        /// Gets the algorithm identifier.
        /// </summary>
        sbyte Id { get; }

        /// <summary>
        /// Gets the algorithm name.
        /// </summary>
        string Name { get; }
    }
}