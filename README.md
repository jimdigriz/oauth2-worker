A [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker) to handle [OAuth2 authentication flows](https://oauth.net/articles/authentication/) suitable for use with in [Single Page Application (SPA)](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps) by storing tokens outside of the [main JavaScript Window Global scope](https://developer.mozilla.org/en-US/docs/Web/API/Window).

It is [considered unsafe to use implicit flow for SPAs](https://auth0.com/blog/oauth2-implicit-grant-and-spa/) but by using a Web Worker as a key vault all tokens can be kept locked away with zero risk of being leaking to third party JavaScript.  This means we can now [request and retain safely the refresh token](https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/) to allow for long lived sessions that do not require regular user action to reauthenticate.

From a developer perspective, requests to HTTP endpoints requiring [bearer tokens](https://www.oauth.com/oauth2-servers/access-tokens/) to access must be pushed through an interface that aims to follow the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) and communicates with the Web Worker to make the request on your behalf which will in turn add the HTTP `Authorization` header for you.

## Design Reasoning

The aim of the project is:

 * keep your tokens safe
 * transparently handle the renewing of your tokens
 * handle requests on your behalf by adding an `Authorization` header
     * later [signing](https://gitlab.com/jimdigriz/oauth2-worker/issues/3)

The choice to use a Web Worker came about as:

 * provides a non-technical end user a familar and bullet proof way to control logging out (close tab or reload page)
     * using a [Service Worker](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API) ([which others have considered](https://developers.google.com/web/updates/2016/06/2-cookie-handoff)) makes hard for the end user to control
 * every tab is its own session
     * Service Workers are shared between tabs so being logged in concurrently as more than one user becomes difficult
 * both a cross-origin IFRAME or Service Worker implementation would be unable to distinguish between authorized (your code) and unauthorized (third party JavaScript) use of its interface as it would come from the [same-origin source](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)

A big advantage of a service worker is that it can be used for the entire lifetime of the refresh token so even after a long period of time the user could remain logged in without having to use cookies.  Fortunately most OAuth2 providers make reauthenticating straight forward, fast and often either no more than a single click affair or backed by their own cookies and immediate so the inconvience is considerably reduced.

## Demo

You will need Python 3 installed and a [`gitlab.com`](https://about.gitlab.com/) account.  If you want to demo against your own OAuth2 provider then do edit [`index.html`](webroot/index.html) per the usage instructions below and 

Now run:

    ./demo.py

Now open http://localhost:5000 in your browser, open developer tools and show the JavaScript console with the network panel.  Now click on 'Login' and inspect the activity.

## Related Links

 * [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)

# Preflight

You will need:

 * OAuth2 provider:
     * supports [discovery (`/.well-known/openid-configuration`)](https://www.rfc-editor.org/rfc/rfc8414.html)
         * including [CORS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
     * supports [PKCE (strongly recommended)](https://oauth.net/2/pkce/)
         * [implicit flow](https://tools.ietf.org/html/rfc6749#section-1.3.2) is supported as a fallback but it will (briefly) expose your `access_token` through `window.onmessage`
 * `client_id` to use with your application

# Usage

You will need to include in your project from the [`webroot`](webroot) directory:

 * **`oauth2.js`:** application interface and imported into your project
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

 * **`client_id`:** your application id (assigned by your OAuth2 provider)
 * **`client_secret [optional]`:** your application secret
     * avoid creating when registering your application in your provider if possible
         * [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-configuring-app-integration.html) lets you do this whilst [GitLab does not](https://docs.gitlab.com/ee/api/oauth2.html)
     * SAP's are considered a [public ('untrusted') client](http://tutorials.jenkov.com/oauth2/client-types.html) as the secret would have to published
 * **`redirect_uri`:** the redirect URL to bounce the the authentication through (there should be no need to change this)
     * this must be registered with your OAuth2 provider
 * **`discovery_endpoint`:** points to the base URL of your OAuth2 endpoint (do not include `/.well-known/openid-configuration`)
     * Google for example uses [https://accounts.google.com](https://developers.google.com/identity/protocols/OpenIDConnect#discovery)
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

We provide a callback that is called when authentication is required, and when called is passed the resolvable parts to promise.  The UI at this point should indicate to the user that an authentication is required and provide an interaction (such as a button/form 'Login' click) to be made.  On the interaction, we resolve the promise we were passed which begins the authentication in a new tab whilst passing in a promise of our own to get feedback on the outcome.

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
