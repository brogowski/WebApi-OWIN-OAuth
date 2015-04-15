using System;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Filters;
using Microsoft.AspNet.Identity;

namespace FullOAuth.ExternalAuthorization
{
    public class ExternalAuthorizationAttribute : Attribute, IOverrideFilter, IAuthenticationFilter
    {
        private readonly HostAuthenticationAttribute _hostAuthenticationAttribute;

        public bool AllowMultiple { get { return false; } }
        public Type FiltersToOverride { get {return  typeof (IAuthenticationFilter);} }

        public ExternalAuthorizationAttribute()
        {
            _hostAuthenticationAttribute = new HostAuthenticationAttribute(DefaultAuthenticationTypes.ExternalCookie);
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            return _hostAuthenticationAttribute.AuthenticateAsync(context, cancellationToken);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            return _hostAuthenticationAttribute.ChallengeAsync(context, cancellationToken);
        }
    }
}