A [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker) to handle [OAuth2 authentication flows](https://oauth.net/articles/authentication/) suitable for use with in [Single Page Application (SPA)](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps) by storing access and refresh tokens outside of the [main JavaScript Window Global scope](https://developer.mozilla.org/en-US/docs/Web/API/Window).

By storing the tokens in the web worker it is made impossible for any third party JavaScript to access them.  For the main application a [Promise based interface](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) is provided to make working with it similar to working with the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API).

## Related Links

 * [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)

# Preflight

You will need:

 * OAuth2 endpoint:
     * supports [discovery (`/.well-known/openid-configuration`)](https://www.rfc-editor.org/rfc/rfc8414.html)
         * including [CORS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
     * supports [PKCE (strongly recommended)](https://oauth.net/2/pkce/) though supported is fallback to [`implicit`](https://tools.ietf.org/html/rfc6749#section-1.3.2)
 * `client_id` to use with your application

Check out the project with:

    git checkout https://gitlab.com/jimdigriz/oauth2-worker.git
    cd oauth2-worker

# Demo

    python3 -m http.server --bind 127.0.0.1 --directory webroot

Now open http://localhost:8000 in your browser.

# Usage

    import { OAuth2 } from './oauth2.js';

    const authorize = (promise) => {
      dispatch('message', { type: 'authorize', promise: promise });
    };
    const oauth2 = new OAuth2({
      client_id: '...',
      redirect_uri: '/oauth2-redirect.html',
      endpoint: {
        discovery: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_...'
      },
      callback: {
        authorize: authorize
      }
    });

## HTTP Headers

Related but not needed for this project, you should set a suitable [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (as well as some other helpful headers) when serving your main application to help you make sure only requests you know about can be made.

A good starting point (and one that supports [AWS Cognito](https://aws.amazon.com/cognito/)) is:

    Content-Security-Policy: default-src 'self' *.amazonaws.com *.amazoncognito.com; frame-ancestors 'none'; report-uri /_/csp-reports
    X-Frame-Options: deny
    X-Content-Type-Options: nosniff
