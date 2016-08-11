using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data;
using System.Configuration;
using System.Web;
using System.Security;
using System.Net;
using System.IO;
using System.Drawing;
using System.Collections.Specialized;

namespace xAuthBellaDati
{
    public class BellaDatiConnection
    {
        BellaDatiBase bdUtil = new BellaDatiBase();
        public enum Method { GET, POST };
        public const string REQUEST_TOKEN = "/oauth/requestToken";
        public const string AUTHORIZE = "/oauth/authorizeRequestToken";
        public const string ACCESS_TOKEN = "/oauth/accessToken";
        public const string XAUTH_ACCESS_TOKEN = "/oauth/accessToken";
        private string _consumerKey = "";
        private string _consumerSecret = "";
        private string _token = "";
        private string _tokenSecret = "";
        private string _verifier = "";

        private string baseUrl;
        public BellaDatiConnection(string baseUrl)
        {
            this.baseUrl = baseUrl;
        }

        #region Properties
        public string ConsumerKey
        {
            get
            {
                if (_consumerKey.Length == 0)
                {
                    _consumerKey = ConfigurationManager.AppSettings["consumerKey"];
                }
                return _consumerKey;
            }
            set { _consumerKey = value; }
        }

        public string ConsumerSecret
        {
            get
            {
                if (_consumerSecret.Length == 0)
                {
                    _consumerSecret = ConfigurationManager.AppSettings["consumerSecret"];
                }
                return _consumerSecret;
            }
            set { _consumerSecret = value; }
        }

        public string Token { get { return _token; } set { _token = value; } }
        public string TokenSecret { get { return _tokenSecret; } set { _tokenSecret = value; } }
        public string Verifier { get { return _verifier; } set { _verifier = value; } }

        #endregion

        /// <summary>
        /// Get the link to BellaDati authorization page for this application.
        /// </summary>
        /// <returns>The url with a valid request token, or a null string.</returns>
        public string AuthorizationLinkGet()
        {
            string ret = null;

            string response = oAuthWebRequest(Method.GET, REQUEST_TOKEN, String.Empty);
            if (response.Length > 0)
            {
                // response contains token and token secret.  We only need the token.
                NameValueCollection qs = HttpUtility.ParseQueryString(response);
                if (qs["oauth_token"] != null)
                {
                    ret = AUTHORIZE + "?oauth_token=" + qs["oauth_token"];
                }
            }
            return ret;
        }

        /// <summary>
        /// Exchange the request token for an access token.
        /// </summary>
        /// <param name="authToken">The oauth_token is supplied by Twitter's authorization page following the callback.</param>
        public void AccessTokenGet(string authToken, string verifier)
        {
            this.Token = authToken;
            this.Verifier = verifier;

            string response = oAuthWebRequest(Method.GET, ACCESS_TOKEN, String.Empty);

            if (response.Length > 0)
            {
                //Store the Token and Token Secret
                NameValueCollection qs = HttpUtility.ParseQueryString(response);
                if (qs["oauth_token"] != null)
                {
                    this.Token = qs["oauth_token"];
                }
                if (qs["oauth_token_secret"] != null)
                {
                    this.TokenSecret = qs["oauth_token_secret"];
                }
            }
        }

        public void xAuthGetAccessToken(string username, string password)
        {

            string link = baseUrl + XAUTH_ACCESS_TOKEN;
            string querystring = "";

            Uri uri = new Uri(link);

            string nonce = bdUtil.GenerateNonce();
            string timeStamp = bdUtil.GenerateTimeStamp();

            //Generate Signature
            string sig = bdUtil.GenerateSignature(uri,
                this.ConsumerKey,
                this.ConsumerSecret,
                this.Token,
                this.TokenSecret,
                this.Verifier,
                username,
                password,
                "POST",
                timeStamp,
                nonce,
                out link,
                out querystring);

            querystring += "&oauth_signature=" + HttpUtility.UrlEncode(sig);
            try
            {
                string ret = WebRequest(Method.POST, XAUTH_ACCESS_TOKEN, "", querystring);
                //Store the Token and Token Secret
                NameValueCollection qs = HttpUtility.ParseQueryString(ret);
                if (qs["oauth_token"] != null)
                {
                    this.Token = qs["oauth_token"];
                }
                else { throw new Exception("Auth failed, auth_token is null!"); }
                if (qs["oauth_token_secret"] != null)
                {
                    this.TokenSecret = qs["oauth_token_secret"];
                }
                else { throw new Exception("Auth failed, auth_token is null!"); }
            }
            catch
            {
                throw new Exception("Authentication failed!");
            }

        }

        public string doGet(string endpoint)
        {
            return oAuthWebRequest(Method.GET, endpoint, String.Empty);
        }

        public string doPost(string endpoint, String postData)
        {
            return oAuthWebRequest(Method.POST, endpoint, postData);
        }

        /// <summary>
        /// Submit a web request using oAuth.
        /// </summary>
        /// <param name="method">GET or POST</param>
        /// <param name="endpoint">suffix of full url.</param>
        /// <param name="postData">Data to post (querystring format)</param>
        /// <returns>The web server response.</returns>
        private string oAuthWebRequest(Method method, string endpoint, string postData)
        {
            string outUrl = "";
            string querystring = "";
            string ret = "";


            //Setup postData for signing.
            //Add the postData to the querystring.
            if (method == Method.POST)
            {
                if (postData.Length > 0)
                {
                    //Decode the parameters and re-encode using the oAuth UrlEncode method.
                    NameValueCollection qs = HttpUtility.ParseQueryString(postData);
                    postData = "";
                    foreach (string key in qs.AllKeys)
                    {
                        if (postData.Length > 0)
                        {
                            postData += "&";
                        }
                        qs[key] = HttpUtility.UrlDecode(qs[key]);
                        qs[key] = bdUtil.UrlEncode(qs[key]);
                        postData += key + "=" + qs[key];

                    }
                    if (endpoint.IndexOf("?") > 0)
                    {
                        endpoint += "&";
                    }
                    else
                    {
                        endpoint += "?";
                    }
                    endpoint += postData;
                }
            }

            Uri uri = new Uri(baseUrl + endpoint);

            string nonce = bdUtil.GenerateNonce();
            string timeStamp = bdUtil.GenerateTimeStamp();

            //Generate Signature
            string sig = bdUtil.GenerateSignature(uri,
                this.ConsumerKey,
                this.ConsumerSecret,
                this.Token,
                this.TokenSecret,
                this.Verifier,
                null,
                null,
                method.ToString(),
                timeStamp,
                nonce,
                out outUrl,
                out querystring);

            querystring += "&oauth_signature=" + HttpUtility.UrlEncode(sig);

            //Convert the querystring to postData
            if (method == Method.POST)
            {
                postData = querystring;
                querystring = "";
            }

            if (querystring.Length > 0)
            {
                outUrl += "?";
            }

            ret = WebRequest(method, endpoint, querystring, postData);

            return ret;
        }

        /// <summary>
        /// Web Request Wrapper
        /// </summary>
        /// <param name="method">Http Method</param>
        /// <param name="endpoint">suffix of Url</param>
        /// <param name="queryString">it is querystring contented consumer key,secret key,Token etc.</param>
        /// <param name="postData">Data to post in querystring format</param>
        /// <returns>The web server response.</returns>
        public string WebRequest(Method method, string endpoint, string queryString, string postData)
        {
            HttpWebRequest webRequest = null;
            StreamWriter requestWriter = null;
            string responseData = "";
            if (!endpoint.StartsWith("/oauth"))
            {
                webRequest = System.Net.WebRequest.Create(baseUrl + endpoint) as HttpWebRequest;
                NameValueCollection nvc = HttpUtility.ParseQueryString(queryString);
                if (webRequest.Address.ToString().Contains("https://service.belladati.com/api"))
                {
                    webRequest.Headers.Add(HttpRequestHeader.Authorization, "OAuth realm=\"" + baseUrl + "\",oauth_consumer_key=\"" + this.ConsumerKey + "\",oauth_token=\"" + nvc["oauth_token"] + "\",oauth_timestamp=\"" + nvc["oauth_timestamp"] + "\",oauth_nonce=\"" + nvc["oauth_nonce"] + "\"");

                }
            }
            else
            {
                webRequest = System.Net.WebRequest.Create(baseUrl + endpoint) as HttpWebRequest;
            }


            webRequest.Method = method.ToString();
            webRequest.ServicePoint.Expect100Continue = false;
            //webRequest.UserAgent  = "Identify your application please.";
            //webRequest.Timeout = 20000;

            if (method == Method.POST)
            {
                webRequest.ContentType = "application/x-www-form-urlencoded";

                //POST the data.
                requestWriter = new StreamWriter(webRequest.GetRequestStream());
                try
                {
                    requestWriter.Write(postData);
                }
                catch
                {
                    throw;
                }
                finally
                {
                    requestWriter.Close();
                    requestWriter = null;
                }
            }

            responseData = WebResponseGet(webRequest);

            webRequest = null;

            return responseData;

        }

        /// <summary>
        /// Process the web response.
        /// </summary>
        /// <param name="webRequest">The request object.</param>
        /// <returns>The response data.</returns>
        public string WebResponseGet(HttpWebRequest webRequest)
        {
            StreamReader responseReader = null;
            string responseData = "";

            try
            {
                responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
                if (webRequest.Address.ToString().Contains("image") || webRequest.Address.ToString().Contains("thumbnail"))
                {
                    Image image = Image.FromStream(webRequest.GetResponse().GetResponseStream());
                    image.Save(@"C:\chart.png");

                }
                responseData = responseReader.ReadToEnd();
            }
            catch (Exception e)
            {

                responseData = "";
                webRequest = null;

                if (this.Token != "")
                {
                    throw new Exception("The endpoint is in incorrect format!");
                }
                else
                {
                    throw new Exception("First, you need to login!");
                }
            }
            finally
            {
                if (webRequest != null)
                {
                    webRequest.GetResponse().GetResponseStream().Close();
                    responseReader.Close();
                    responseReader = null;
                }
            }
            return responseData;
        }
    }
}
