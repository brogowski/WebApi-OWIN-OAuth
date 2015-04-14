using System;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using Owin;
using WebApiOAuthTest.Authorization;
using WebApiOAuthTest.ExternalAuthorization;

namespace WebApiOAuthTest
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions GoogleAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(GetWebApiConfig());
        }

        private void ConfigureOAuth(IAppBuilder app)
        {
            app.UseOAuthAuthorizationServer(GetOAuthServerOptions());
            app.UseOAuthBearerAuthentication((OAuthBearerOptions = GetOAuthOptions()));

            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);

            app.UseGoogleAuthentication((GoogleAuthOptions = GetGoogleAuthOptions()));
        }

        private static OAuthAuthorizationServerOptions GetOAuthServerOptions()
        {
            return new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                Provider = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };
        }

        private GoogleOAuth2AuthenticationOptions GetGoogleAuthOptions()
        {
            return new GoogleOAuth2AuthenticationOptions
            {
                ClientId = "x",
                ClientSecret = "x",
                Provider = new ClaimsBasedGoogleAuthenticationProvider()
            };
        }

        private OAuthBearerAuthenticationOptions GetOAuthOptions()
        {
            return new OAuthBearerAuthenticationOptions();
        }

        private HttpConfiguration GetWebApiConfig()
        {
            HttpConfiguration config = new HttpConfiguration();

            var jsonFormatter = config.Formatters.OfType<JsonMediaTypeFormatter>().First();
            jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new {id = RouteParameter.Optional}
                );

            return config;
        }
    }
}
