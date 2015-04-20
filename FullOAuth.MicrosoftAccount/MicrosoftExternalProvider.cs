using FullOAuth.ExternalAuthorization.Extensions;
using FullOAuth.OWIN;
using Microsoft.Owin.Security.MicrosoftAccount;
using Owin;

namespace FullOAuth.Microsoft
{
    public class MicrosoftExternalProvider : IExternalProvider
    {
        private readonly IExternalProviderTokenValidator _tokenValidator = new MicrosoftTokenValidator();
        private readonly string _clientId;
        private readonly string _clientSecret;

        public MicrosoftExternalProvider(string clientId, string clientSecret)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        public void Setup(IAppBuilder app)
        {
            app.UseMicrosoftAccountAuthentication(GetMicrosoftAuthOptions());
        }

        private MicrosoftAccountAuthenticationOptions GetMicrosoftAuthOptions()
        {
            return new MicrosoftAccountAuthenticationOptions
            {
                Provider = new ClaimsBasedMicrosoftAuthenticationProvider(),                
                ClientId = _clientId,
                ClientSecret = _clientSecret
            };
        }

        public IExternalProviderTokenValidator GetTokenValidator()
        {
            return _tokenValidator;
        }
    }
}
