using System.Collections.Generic;

namespace FullOAuth.ExternalAuthorization.Extensions
{
    public interface IAccessTokenGenerator
    {
        IReadOnlyDictionary<string, string> GenerateAccessToken(string userName);
    }
}