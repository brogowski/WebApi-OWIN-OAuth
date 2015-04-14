using System.Web.Http;

namespace WebApiOAuthTest.Controllers
{
    public class ContentController : ApiController
    {
        [Authorize(Roles = "user")]
        public string Get()
        {           
            return "You are authorized";
        }
    }
}