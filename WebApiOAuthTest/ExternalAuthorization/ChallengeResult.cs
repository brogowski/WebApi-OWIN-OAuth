using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace FullOAuth.ExternalAuthorization
{
    class ChallengeResult : IHttpActionResult
    {
        private readonly string _loginProvider;
        private readonly HttpRequestMessage _request;

        public ChallengeResult(string loginProvider, HttpRequestMessage request)
        {
            _loginProvider = loginProvider;
            _request = request;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            _request.GetOwinContext().Authentication.Challenge(_loginProvider);

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                RequestMessage = _request
            });
        }
    }
}
