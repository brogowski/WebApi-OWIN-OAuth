using System.Security.Claims;
using System.Threading.Tasks;
using FullOAuth.Properties;
using Microsoft.Owin.Security.Facebook;

namespace FullOAuth.Facebook
{
    class ClaimsBasedFacebookAuthenticationProvider : FacebookAuthenticationProvider
    {
        public override Task Authenticated(FacebookAuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim(Constants.ExternalAccessTokenKey, context.AccessToken,
                null, "Facebook"));
            return Task.FromResult<object>(null);
        }
    }
}
