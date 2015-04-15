using System.Collections.Generic;
using System.Linq;
using FullOAuth.AuthorizationServer;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace FullOAuth.OWIN
{
    public static class OwinExtensions
    {
        internal static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        internal static IEnumerable<IExternalProvider> ExternalProviders { get; private set; } 

        public static void UseFullOAuth(this IAppBuilder app, FullOAuthSettings settings, FullOAuthExtensions extensions)
        {
            ConfigureOAuth(app, settings, extensions);
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
        }

        private static void ConfigureOAuth(IAppBuilder app, FullOAuthSettings settings, FullOAuthExtensions extensions)
        {
            app.UseOAuthAuthorizationServer(GetOAuthServerOptions(settings, extensions));
            app.UseOAuthBearerAuthentication((OAuthBearerOptions = GetOAuthOptions()));

            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);

            foreach (var externalProvider in extensions.ExternalProviders)
            {
                externalProvider.Setup(app);
            }

            ExternalProviders = extensions.ExternalProviders.ToArray();
        }

        private static OAuthAuthorizationServerOptions GetOAuthServerOptions(FullOAuthSettings settings, FullOAuthExtensions extensions)
        {
            return new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString(settings.TokenEndpointPath),
                AccessTokenExpireTimeSpan = settings.AccessTokenExpireTimeSpan,
                Provider = new SimpleAuthorizationServerProvider(extensions.ClientRepo, extensions.Hasher, extensions.AccessValidator),
                RefreshTokenProvider = new SimpleRefreshTokenProvider(extensions.Hasher, extensions.RefreshTokenRepo)
            };
        }

        private static OAuthBearerAuthenticationOptions GetOAuthOptions()
        {
            return new OAuthBearerAuthenticationOptions();
        }
    }
}
