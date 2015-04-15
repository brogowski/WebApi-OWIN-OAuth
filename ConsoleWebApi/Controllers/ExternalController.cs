using System.Threading.Tasks;
using System.Web.Http;
using ConsoleWebApi.BL;
using ConsoleWebApi.DAL;
using FullOAuth.ExternalAuthorization;

namespace ConsoleWebApi.Controllers
{
    public class ExternalController : ExternalLoginController
    {
        public ExternalController() : base(new UserRepo(), new UserRepo(), new ClientRepo(), new SimpleClaimsProvider())
        {
        }

        [ExternalAuthorization]
        [AllowAnonymous]
        [HttpGet]
        [Route("Login")]
        public async Task<IHttpActionResult> Login(string provider, string error = null)
        {
            return await ExternalLoginAsync(provider, error);
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(string userName, string provider, string externalAccessToken)
        {
            return await ExternalRegisterAsync(new RegisterExternalBindingModel
                {
                    UserName = userName,
                    Provider = provider,
                    ExternalAccessToken = externalAccessToken
                });
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("LocalAccessToken")]
        public async Task<IHttpActionResult> LocalAccessToken(string provider, string externalAccessToken)
        {
            return await ObtainLocalAccessTokenAsync(provider, externalAccessToken);
        }
    }
}
