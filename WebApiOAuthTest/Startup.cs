using System.Web.Http;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace WebApiOAuthTest
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions GoogleAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);

            app.UseOAuthBearerAuthentication((OAuthBearerOptions = GetOAuthOptions()));
            app.UseGoogleAuthentication((GoogleAuthOptions = GetGoogleAuthOptions()));

            app.UseWebApi(GetWebApiConfig());
        }

        private GoogleOAuth2AuthenticationOptions GetGoogleAuthOptions()
        {
            return new GoogleOAuth2AuthenticationOptions
            {
                ClientId = "xxx",
                ClientSecret = "xxx",
                Provider = new GoogleAuthProvider()
            };
        }

        private OAuthBearerAuthenticationOptions GetOAuthOptions()
        {
            return new OAuthBearerAuthenticationOptions();
        }

        private HttpConfiguration GetWebApiConfig()
        {
            HttpConfiguration config = new HttpConfiguration();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new {id = RouteParameter.Optional}
                );
            return config;
        }

    }
}
