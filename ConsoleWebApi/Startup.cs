using System;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;
using ConsoleWebApi.BL;
using ConsoleWebApi.DAL;
using FullOAuth.Facebook;
using FullOAuth.Google;
using FullOAuth.OWIN;
using Newtonsoft.Json.Serialization;
using Owin;

namespace ConsoleWebApi
{
    public class Startup
    {

        public void Configuration(IAppBuilder app)
        {
            app.UseFullOAuth(GetSettings(), GetExtensions());

            app.UseWebApi(GetWebApiConfig());
        }

        private FullOAuthExtensions GetExtensions()
        {
            return new FullOAuthExtensions
            {
                Hasher = new SimpleHasher(),
                AccessValidator = new UserRepo(),
                ClientRepo = new ClientRepo(),
                RefreshTokenRepo = new RefreshTokenRepo(),
                ExternalProviders = new IExternalProvider[] 
                {
                    new GoogleOAuth2ExternalProvider("xxx", "xxx"),
                    new FacebookExternalProvider("xxx", "xxx", "xxx")
                }
            };
        }

        private FullOAuthSettings GetSettings()
        {
            return new FullOAuthSettings
            {
                TokenEndpointPath = "/token",
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                AllowInsecureHttp = true
            };
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
