using System.Web.Http;
using WebApiOAuthTest.DAL;

namespace WebApiOAuthTest.Controllers
{
    public class RegisterController : ApiController
    {
        public IHttpActionResult Post(string userName, string password)
        {
            UserRepo.RegisterUser(userName, password);

            return Ok();
        }
    }
}