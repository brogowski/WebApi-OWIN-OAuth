using System;

namespace FullOAuth.OWIN
{
    public class FullOAuthSettings
    {
        public string TokenEndpointPath { get; set; }
        public TimeSpan AccessTokenExpireTimeSpan { get; set; }
        public bool AllowInsecureHttp { get; set; }
    }
}