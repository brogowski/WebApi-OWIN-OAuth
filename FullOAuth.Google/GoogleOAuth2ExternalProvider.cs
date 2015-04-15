using FullOAuth.ExternalAuthorization.Extensions;
using FullOAuth.OWIN;
using Microsoft.Owin.Security.Google;
using Owin;

namespace FullOAuth.Google
{
    public class GoogleOAuth2ExternalProvider : IExternalProvider
    {
        private GoogleOAuth2AuthenticationOptions _authenticationOptions;
        private IExternalProviderTokenValidator _tokenValidator;
        private readonly string _clientId;
        private readonly string _clientSecret;

        public GoogleOAuth2ExternalProvider(string clientId, string clientSecret)
        {            
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        public void Setup(IAppBuilder app)
        {
            _authenticationOptions = GetGoogleAuthOptions();
            _tokenValidator = new GoogleOAuth2TokenValidator(_authenticationOptions);

            app.UseGoogleAuthentication(_authenticationOptions);
        }

        public IExternalProviderTokenValidator GetTokenValidator()
        {
            return _tokenValidator;
        }

        private GoogleOAuth2AuthenticationOptions GetGoogleAuthOptions()
        {
            return new GoogleOAuth2AuthenticationOptions
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                Provider = new ClaimsBasedGoogleAuthenticationProvider()
            };
        }
    }
}