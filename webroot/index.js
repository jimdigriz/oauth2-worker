import { OAuth2 } from './oauth2.js';

const authorize = (promise) => {
  const button = document.getElementById('button');
  button.textContent = 'Login';
  button.removeAttribute('disabled');
  button.onclick = function(e) {
    e.preventDefault();

    new Promise((resolve, reject) => {
      button.setAttribute('disabled', '');
      button.textContent = 'Logging in...';
      promise.resolve({ resolve: resolve, reject: reject });
    }).then(
	  data => {
        console.log('success', data);
        button.textContent = 'Logged in';
      },
      data => {
        console.log('failed', data);
        button.textContent = 'Login Failed';
      }
    ).catch(error => {
      console.log('error', error);
      button.textContent = 'Login Error';
    });
  };
};

const oauth2 = new OAuth2({
  client_id: '3ea93227a55ed2db80cfbd51db973eed63fe3158167524bf64520985043b3fed',
  redirect_uri: '/oauth2-redirect.html',
//      discovery_endpoint: 'https://gitlab.com',	// https://gitlab.com/gitlab-org/gitlab/-/issues/209259
  discovery_document: '{"issuer":"https://gitlab.com","authorization_endpoint":"https://gitlab.com/oauth/authorize","token_endpoint":"https://gitlab.com/oauth/token","revocation_endpoint":"https://gitlab.com/oauth/revoke","introspection_endpoint":"https://gitlab.com/oauth/introspect","userinfo_endpoint":"https://gitlab.com/oauth/userinfo","jwks_uri":"https://gitlab.com/oauth/discovery/keys","scopes_supported":["api","read_user","read_repository","write_repository","read_registry","sudo","openid","profile","email"],"response_types_supported":["code","token"],"response_modes_supported":["query","fragment"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"claim_types_supported":["normal"],"claims_supported":["iss","sub","aud","exp","iat","sub_legacy","name","nickname","email","email_verified","website","profile","picture","groups"]}',
  authorize_callback: authorize,
  scopes: [ 'openid', 'email', 'profile' ]
});

oauth2.whoami().then(whoami => {
  document.getElementById('name').textContent = whoami.name;
  document.getElementById('email').textContent = whoami.email;
});

oauth2.fetch(location.origin + '/userinfo').then(response => {
  console.log('fetch', response)
});
