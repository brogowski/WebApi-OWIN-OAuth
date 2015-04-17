using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Google;
using FullOAuth.Properties;

namespace FullOAuth.Google
{
    class ClaimsBasedGoogleAuthenticationProvider : GoogleOAuth2AuthenticationProvider
    {
        public override Task Authenticated(GoogleOAuth2AuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim(Constants.ExternalAccessTokenKey, context.AccessToken,
                null, "Google"));
            return base.Authenticated(context);
        }
    }
}
