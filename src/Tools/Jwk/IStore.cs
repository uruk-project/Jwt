using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken.Tools.Jwk
{
    public interface IStore
    {
        string Read(string inputPath);
        void Write(string outputPath, string key, bool force);
        X509Certificate2 LoadX509(string inputPath, string? password);
    }
}
