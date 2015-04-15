using FullOAuth.AuthorizationServer.Extensions;

namespace ConsoleWebApi.BL
{
    internal class SimpleHasher : IHashingProvider
    {
        public string Hash(string input)
        {
            return input;
        }
    }
}