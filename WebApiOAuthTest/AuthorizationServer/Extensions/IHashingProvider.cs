namespace FullOAuth.AuthorizationServer.Extensions
{
    public interface IHashingProvider
    {
        string Hash(string input);
    }
}