// https://stackoverflow.com/a/2117523
function uuidv4() {
	return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
		(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
	);
}

// https://stackoverflow.com/a/42334410
function ab2bstr(ab) {
	return new Uint8Array(ab).reduce((data, byte) => {
		return data + String.fromCharCode(byte);
	}, '');
}

function base64url_encode(s) {
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64url_decode(s) {
	return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

const pending = {};

let _config = null;
const config = new Promise((resolve, reject) => {
	_config = resolve;
}).then(data => {
	function validate(discovery) {
		discovery = Object.keys(data.data.discovery_overlay || {}).reduce((a, k) => {
			a[k] = data.data.discovery_overlay[k];
			return a;
		}, discovery);

		// https://tools.ietf.org/html/rfc8414
		discovery.grant_types_supported = discovery.grant_types_supported || [ 'authorization_code', 'implicit' ];
		discovery.token_endpoint_auth_methods_supported = discovery.token_endpoint_auth_methods_supported || [ 'client_secret_basic' ];

		try {
			ok: switch (true) {
			case discovery.grant_types_supported.includes('authorization_code'):
				switch (true) {
				case discovery.response_types_supported.includes('code'):
					switch (true) {
					case (discovery.code_challenge_methods_supported || []).length == 0:
					case (discovery.code_challenge_methods_supported || []).includes('S256'):
					case (discovery.code_challenge_methods_supported || []).includes('plain'):
						break ok;
					}
				}
				throw new Error("unable to use 'authorization_code' grant");
			case discovery.grant_types_supported.includes('implicit'):
				switch (true) {
				case discovery.response_types_supported.includes('token'):
					break ok;
				}
				throw new Error("unable to use 'implicit' grant");
			default:
				throw new Error("neither 'authorization_code' or 'implicit' supported");
			}

			if (data.data.client_secret) {
				switch (true) {
				case discovery.token_endpoint_auth_methods_supported.includes('client_secret_basic'):
				case discovery.token_endpoint_auth_methods_supported.includes('client_secret_post'):
					break;
				default:
					throw new Error("unable to use 'client_secret'");
				}
			}
		} catch(error) {
			console.error(error);
			return Promise.reject(error);
		}

		if (data.data.scopes && discovery.scopes_supported) {
			const overlap = data.data.scopes.filter(scope => discovery.scopes_supported.includes(scope));
			if (overlap.length < data.data.scopes.length)
				return Promise.reject(new Error('not all requested scopes are available'));
		}

		data.data.openid = discovery;

		return data.data;
	}

	if (!data.data.discovery_endpoint)
		return validate({});

	return fetch(data.data.discovery_endpoint + '/.well-known/openid-configuration').then(response => {
		if (!response.ok) return reject(new Error(response.statusText));
		return response.json().then(discovery => validate(discovery));
	});
});

let __tokens = Promise.reject({});
function _tokens(refresh) {
	function request(config, params) {
		const headers = {};

		params.append('client_id', config.client_id);
		if (config.client_secret) {
			switch (true) {
			case config.openid.token_endpoint_auth_methods_supported.includes('client_secret_basic'):
				headers['authorization'] = 'Basic ' + btoa([ config.client_id, config.client_secret ].join(':'));
				break;
			case config.openid.token_endpoint_auth_methods_supported.includes('client_secret_post'):
				params.append('client_secret', config.client_secret);
				break;
			}
		}

		return fetch(config.openid.token_endpoint, {
			method: 'POST',
			headers: headers,
			body: params
		}).then(response => {
			if (response.status == 401 && refresh)
				return _tokens();
			if (!response.ok)
				return Promise.reject(new Error(response.statustext));
			return response.json();
		}).then(json => {
			json._ts = performance.now();
			return json;
		});
	}

	function authorize(config, params, code_verifier) {
		const id = uuidv4();

		params.append('client_id', config.client_id);
		params.append('redirect_uri', location.origin + config.redirect_uri),
		params.append('state', id);

		if (config.scopes)
			params.append('scope', config.scopes.join(' '));

		// https://developers.google.com/identity/protocols/OAuth2WebServer#offline
		if (config.discovery_endpoint == 'https://accounts.google.com') {
			params.append('access_type', 'offline');
			params.append('prompt', 'consent');
		}

		return new Promise((resolve, reject) => {
			pending[id] = { resolve: resolve, reject: reject };
			postMessage({ type: 'authorize', id: id, data: {
				uri: config.openid.authorization_endpoint + '?' + params.toString()
			}});
		}).then(redirect => {
			if (redirect.data.access_token) {
				redirect.data._ts = performance.now();
				return redirect.data;
			}

			const params = new URLSearchParams();

			params.append('grant_type', 'authorization_code');
			params.append('redirect_uri', location.origin + config.redirect_uri);
			params.append('code', redirect.data.code);
			if (code_verifier)
				params.append('code_verifier', code_verifier);

			return request(config, params).then(
				json => {
					postMessage({ id: id, ok: true });
					return json;
				},
				reason => {
					postMessage({ id: id, ok: false, data: { error: reason.message } });
					return Promise.reject(reason);
				}
			);
		}).catch(error => Promise.reject(error));
	}

	return Promise.allSettled([config, __tokens]).then(args0 => {
		const [ config, tokens ] = args0;

		if (tokens.value && !refresh)
			return tokens.value;

		const params = new URLSearchParams();
		const args = [];
		let cb = null;

		ok: switch (true) {
		case refresh && !!(tokens.value || {}).refresh_token:
			params.append('grant_type', 'refresh_token');
			params.append('refresh_token', (tokens.value || {}).refresh_token);
			cb = function(args) {
				const [ ] = args;
				return request(config.value, params);
			}
			break ok;
		case config.value.openid.grant_types_supported.includes('authorization_code'):
			switch (true) {
			case config.value.openid.response_types_supported.includes('code'):
				params.append('response_type', 'code');

				if (!config.value.openid.code_challenge_methods_supported) {
					cb = function(args) {
						const [ ] = args;
						return authorize(config.value, params);
					}
					break ok;
				}

				const code_verifier = base64url_encode(ab2bstr(crypto.getRandomValues(new Uint8Array(32))));

				switch (true) {
				case (config.value.openid.code_challenge_methods_supported || []).includes('S256'):
					params.append('code_challenge_method', 'S256');
					args.push(crypto.subtle.digest(
						{
							name: 'SHA-256'
						},
						(new TextEncoder()).encode(code_verifier)
					));
					cb = function(args) {
						const [ code_challenge ] = args;
						params.append('code_challenge', base64url_encode(ab2bstr(code_challenge)));
						return authorize(config.value, params, code_verifier);
					};
					break ok;
				case (config.value.openid.code_challenge_methods_supported || []).includes('plain'):
					params.append('code_challenge_method', 'plain');
					params.append('code_challenge', code_verifier);
					cb = function(args) {
						const [ ] = args;
						return authorize(config.value, params, code_verifier);
					}
					break ok;
				}
			}
			return Promise.reject(new Error('NYI'));
		case config.value.openid.grant_types_supported.includes('implicit'):
			switch (true) {
			case config.value.openid.response_types_supported.includes('token'):
				params.append('response_type', 'token');
				cb = function(args) {
					const [ ] = args;
					return authorize(config.value, params);
				}
				break ok;
			}
			return Promise.reject(new Error('NYI'));
		default:
			return Promise.reject(new Error('NYI'));
		}

		return Promise.all(args).then(cb);
	});
}
function tokens(refresh) {
	if (refresh) return _tokens(refresh);

	return __tokens.then(
		toks => {
			if (toks._ts + (toks.expires_in * 1000) < performance.now())
				return tokens(true);
			return toks;
		},
		reason => {
			__tokens = _tokens().then(
				tokens => {
					config.then(config => {
						// we use +2 so the demo sees the 401
						if (tokens.expires_in < (config.expires_in || -2) + 2) return;
						tokens.expires_in = config.expires_in + 2;
						__tokens = Promise.resolve(tokens);
						setTimeout(function(){
							tokens.access_token = 'EXPIRED';
							__tokens = Promise.resolve(tokens);
						}, config.expires_in * 1000);
					});
					return tokens;
				},
				reason => {
					console.error('token', reason);
				}
			);
			return __tokens;
		}
	);
}

function _do_fetch(data, refresh) {
	return tokens(refresh).then(tokens => {
		data.data.options = data.data.options || {};
		data.data.options.headers = data.data.options.headers || {};
		data.data.options.headers['authorization'] = [ tokens.token_type, tokens.access_token ].join(' ');

		return fetch(data.data.uri, data.data.options).then(response => {
			if (response.status == 401 && !refresh)
				return _do_fetch(data, true);
			return response;
		});
	});
}

function do_whoami(data) {
	tokens().then(tokens => {
		if (tokens.id_token && data.data.type != 'userinfo') {
			const json = JSON.parse(base64url_decode(tokens.id_token.split('.')[1]));
			return postMessage({ id: data.id, ok: true, data: json });
		}
		config.then(config => {
			if (!config.openid.userinfo_endpoint)
				return postMessage({ id: data.id, ok: true, data: null });
			data.data = {
				uri: config.openid.userinfo_endpoint
			};
			_do_fetch(data).then(response => {
				return response.json();
			}).then(json => {
				postMessage({ id: data.id, ok: true, data: json });
			}).catch(error => {
				postMessage({ id: data.id, ok: false, data: { error: error.message } });
			});
		});
	});
}

function do_fetch(data) {
	let response = null;

	_do_fetch(data).then(response0 => {
		response = response0;
		return response0.text();
	}).then(body => {
		const headers = {};
		for (let pair of response.headers.entries())
			headers[pair[0].toLowerCase()] = pair[1];
		postMessage({ id: data.id, ok: true, data: {
			ok: response.ok,
			status: response.status,
			headers: headers,
			body: body
		}});
	}).catch(error => {
		postMessage({ id: data.id, ok: false, data: { error: error.message } });
	});
}

onmessage = function(event) {
//	console.info(event.data);

	let dispatch = null;

	switch (event.data.type) {
	case '_config':
		dispatch = _config;
		break;
	case 'whoami':
		dispatch = do_whoami;
		break;
	case 'fetch':
		dispatch = do_fetch;
		break;
	default:
		if (!(event.data.id in pending))
			return console.warn('orphan', event.data);
		const promise = pending[event.data.id];
		delete pending[event.data.id];
		dispatch = event.data.ok ? promise.resolve : promise.reject;
	}

	dispatch(event.data);
}
