using System.Security.Claims;
using FullOAuth.ExternalAuthorization.Extensions;

namespace ConsoleWebApi.BL
{
    public class SimpleClaimsProvider : IClaimsProvider
    {
        public void SetClaimsForUser(string userName, ClaimsIdentity identity)
        {
            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
        }
    }
}