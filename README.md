A [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker) to handle [OAuth2 authentication flows](https://oauth.net/articles/authentication/) suitable for use with in [Single Page Application (SPA)](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps) by storing tokens outside of the [main JavaScript Window Global scope](https://developer.mozilla.org/en-US/docs/Web/API/Window).

It is [generally considered unsafe to use `implicit` grant with SPA](https://auth0.com/blog/oauth2-implicit-grant-and-spa/) but in this project we use a Web Worker as a trusted key vault which keeps all your tokens locked away with zero risk of any third party JavaScript being able to access them.  This means we can now even retain the refresh token too to support long user sessions without regular interactive reauthentication.

Interaction with the Web Worker is via a [Promise based interface](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) that tries mimic the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API); requests will have a suitable HTTP `Authorization` header added to them.

## Related Links

 * [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)

# Preflight

You will need:

 * OAuth2 endpoint:
     * supports [discovery (`/.well-known/openid-configuration`)](https://www.rfc-editor.org/rfc/rfc8414.html)
         * including [CORS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
     * supports [PKCE (strongly recommended)](https://oauth.net/2/pkce/)
         * [`implicit`](https://tools.ietf.org/html/rfc6749#section-1.3.2) is supported as a fallback but it will (briefly) expose your `access_token` through `window.onmessage`
 * `client_id` to use with your application

Check out the project with:

    git checkout https://gitlab.com/jimdigriz/oauth2-worker.git
    cd oauth2-worker

# Demo

    ./demo.py

Now open http://localhost:5000 in your browser, open developer tools and show the JavaScript console and click on Login.

# Usage

You will need to include in your project from the [`webroot`](webroot) directory:

 * **`oauth2.js`:** application interface
 * **`oauth2-worker.js`:** web worker
 * **`oauth2-redirect.html` and `oauth2-redirect.js`:** page used to bounce the authentication off

It may help to start looking at the [example demo `index.html`](webroot/index.html) and then use the following as a reference.

## `new OAuth2()`

We start by initialising a fresh OAuth2 instance:

    const oauth2 = new OAuth2({
      client_id: '...',
      redirect_uri: '/oauth2-redirect.html',
      discovery_endpoint: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_...',
      authorize_callback: authorize
    });

Where:

 * **`client_id`:** is the identifier supplied by your OAuth2 platform for your client application
 * **`redirect_uri`:** the redirect URL to bounce the the authentication through (this is required, but there should be no need to change it)
     * this must be registered with your OAuth2 provider
 * **`discovery_endpoint`:** points to the base URL of your OAuth2 endpoint (do not include `/.well-known/openid-configuration`)
     * Google for example uses [https://accounts.google.com](https://developers.google.com/identity/protocols/OpenIDConnect#discovery)
     * if your platform does not support discovery then you must supply:
         * **`authorization_endpoint` [required]**: this is where the user logins in using their credentials
         * **`token_endpoint` [recommended]:** without this `PKCE` (`code` flow) is not supported and the more risky `implicit` flow has to be used
         * **`userinfo_endpoint` [optional]:** endpoint that can provide details about the user bearing the token
 * **`authorize_callback`:** there is no `login` method as access tokens can expire at any given moment.  This provides a callback (detailed below) that has the application provide a user interaction to start the authentication 

### `authorize_callback`

Assuming you have a button on your page (with the ID `button`) you can use something like:

    const authorize = (promise) => {
      // set up the UI to reflect we need to log in but
      // as our login window will be opened in a new tab,
      // we require an user interaction (click) to open it
      document.getElementById('button').onclick = function(e) {
        e.preventDefault();

        new Promise((resolve, reject) => {
          // set up the UI to reflect that we are attempting to login
          promise.resolve({ resolve: resolve, reject: reject });
        }).then(data => {
          // set up the UI to reflect that login has been successful
          console.log('success', data);
        }).catch(error => {
          // set up the UI to reflect that login has failed
          console.log('failed', error);
        });
      };
    };

We provide a callback that is called when authentication is required, and when called passes the resolvable parts to promise.  The UI at this point should be set up to indicate to the user that an authentication is required and a interaction (such as a button/form click) to be made.  On the interaction, we resolve the promise we were passed which kicks off the authentication, and in doing so we pass in a promise of our own to get feedback on the outcome of the authentication.

## `.whoami()`

    oauth2.whoami().then(whoami => { console.log(whoami) });

Returns the JSON parsed version of either:

 * `id_token` from the authentication
 * if no `id_token` was provided by the endpoint, then [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) is consulted

If nothing is available, then `null` is returned.

## `.fetch()`

You should refer to the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) for a overview of this.

    oauth2.fetch('https://...', { method: 'PUT', headers: { 'Content-Type': ... }, body: ..., ... }).then(response => {
      console.log(response);
    });

Differing to the Fetch API, `body` is either a string ([instance types are not available](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#Body) as they are not serialisable to the Web Worker) or [`URLSearchParams`](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams) (which will force `Content-Type` to `application/x-www-form-urlencoded; charset=utf-8`).

The response on success is:

    { ok: true, status: 200, headers: { ... }, body: "..." }

On error, response is:

    { ok: false, error: "..." }

## HTTP Headers

Related but not needed for this project, you should set a suitable [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (as well as some other helpful headers) when serving your main application to help you make sure only requests you know about can be made.

A good starting point (and one that supports [AWS Cognito](https://aws.amazon.com/cognito/)) is:

    Content-Security-Policy: default-src 'self' *.amazonaws.com *.amazoncognito.com; frame-ancestors 'none'; report-uri /_/csp-reports
    X-Frame-Options: deny
    X-Content-Type-Options: nosniff
