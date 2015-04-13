using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace WebApiOAuthTest
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            app.UseOAuthBearerAuthentication((OAuthBearerOptions = GetOAuthOptions()));
            
            app.UseWebApi(GetWebApiConfig());
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
