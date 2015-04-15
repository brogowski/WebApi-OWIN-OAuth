using System.Security.Claims;

namespace FullOAuth.ExternalAuthorization.Extensions
{
    public interface IClaimsProvider
    {
        void SetClaimsForUser(string userName, ClaimsIdentity identity);
    }
}