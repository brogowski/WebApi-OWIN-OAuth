using System.Security.Claims;
using System.Threading.Tasks;
using FullOAuth.Properties;
using Microsoft.Owin.Security.MicrosoftAccount;

namespace FullOAuth.Microsoft
{
    class ClaimsBasedMicrosoftAuthenticationProvider : MicrosoftAccountAuthenticationProvider
    {
        public override Task Authenticated(MicrosoftAccountAuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim(Constants.ExternalAccessTokenKey, context.AccessToken, null, "Microsoft"));
            return base.Authenticated(context);
        }
    }
}
