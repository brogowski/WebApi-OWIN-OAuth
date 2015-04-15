using System.Web.Http;

namespace ConsoleWebApi.Controllers
{
    public class SecuredContentController : ApiController
    {
        [Authorize(Roles = "user")]
        public string Get()
        {           
            return "You are authorized";
        }
    }
}