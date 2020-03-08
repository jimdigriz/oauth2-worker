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

const untilOnline = new Promise(function _untilOnline(resolve, reject) {
	function cb() {
		addEventListener('offline', function(){ untilOnline = new Promise(_untilOnline) }, { once: true });
		return resolve();
	}
	if (navigator.onLine)
		return cb();
	addEventListener('online', cb, { once: true });
});

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

			if (data.data.scopes && discovery.scopes_supported) {
				const overlap = data.data.scopes.filter(scope => discovery.scopes_supported.includes(scope));
				if (overlap.length < data.data.scopes.length)
					throw new Error('not all requested scopes are available');
			}
		} catch(error) {
			return Promise.reject(error);
		}

		return Promise.resolve(discovery);
	}

	return new Promise((resolve, reject) => {
		if (!data.data.discovery_endpoint)
			return validate({});

		return untilOnline.then(() => {
			return fetch(data.data.discovery_endpoint + '/.well-known/openid-configuration').then(response => {
				if (!response.ok) return reject(new Error(response.statusText));
				return response.json().then(discovery => validate(discovery));
			}).then(resolve).catch(reject);
		});
	}).then(
		openid => {
			postMessage({ type: 'state', ok: true, data: { state: 'ready' } });
			data.data.openid = openid;
			return data.data;
		},
		reason => {
			postMessage({ type: 'state', ok: false, data: { error: reason.message } });
			return new Promise();	// stall
		}
	);
});

let __tokens = null;
function _tokens(config, refresh) {
	function request(params) {
		const headers = new Headers();

		params.append('client_id', config.client_id);
		if (config.client_secret) {
			switch (true) {
			case config.openid.token_endpoint_auth_methods_supported.includes('client_secret_basic'):
				headers.append('authorization', 'Basic ' + btoa([ config.client_id, config.client_secret ].join(':')));
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
			if (response.status == 401 && !refresh) {
				__tokens = null;
				return _tokens(config, true);
			}
			if (!response.ok)
				return Promise.reject(new Error(response.statustext));
			return response.json();
		}).then(json => {
			json._ts = performance.now();
			return json;
		});
	}

	function authorize(params, code_verifier) {
		const id = uuidv4();
		const key = uuidv4();

		params.append('client_id', config.client_id);
		params.append('redirect_uri', location.origin + config.redirect_uri),
		params.append('state', [id, key].join(':'));

		if (config.scopes)
			params.append('scope', config.scopes.join(' '));

		// https://developers.google.com/identity/protocols/OpenIDConnect#refresh-tokens
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
			const ts = new Date().getTime() + new Date().getTimezoneOffset();
			if (!(redirect.ts > ts - 10 && redirect.ts < ts + 10))
				throw new Error('redirect has bad ts');

			const encoder = new TextEncoder();

			return crypto.subtle.importKey(
				'raw',
				encoder.encode(key),
				{
					name: 'PBKDF2'
				},
				false,
				['deriveKey']
			).then(key => {
				return crypto.subtle.deriveKey(
					{
						name: 'PBKDF2',
						salt: redirect.salt,
						iterations: 1000,
						hash: {
							name: 'SHA-256'
						}
					},
					key,
					{
						name: 'AES-GCM',
						length: 256
					},
					false,
					['decrypt']
				)
			}).then(key => {
				return crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: redirect.iv,
						additionalData: encoder.encode(redirect.ts)
					},
					key,
					redirect.data
				)
			}).then(plaintext => {
				const data = Object.fromEntries((new URLSearchParams(ab2bstr(plaintext))).entries());

				if (data.access_token) {
					data._ts = performance.now();
					return data;
				}

				const params = new URLSearchParams();

				params.append('grant_type', 'authorization_code');
				params.append('redirect_uri', location.origin + config.redirect_uri);
				params.append('code', data.code);
				if (code_verifier)
					params.append('code_verifier', code_verifier);

				return request(params).then(json => {
					postMessage({ id: id, ok: true });
					return json;
				});
			});
		}).catch(error => {
			postMessage({ id: id, ok: false, data: { error: error.message } });
			return Promise.reject(error);
		});
	}

	const params = new URLSearchParams();
	const args = [];
	let cb = null;

	ok: switch (true) {
	case !!(__tokens || {}).refresh_token:
		params.append('grant_type', 'refresh_token');
		params.append('refresh_token', __tokens.refresh_token);
		cb = function(args) {
			const [ ] = args;
			return request(params);
		}
		break ok;
	case config.openid.grant_types_supported.includes('authorization_code'):
		switch (true) {
		case config.openid.response_types_supported.includes('code'):
			params.append('response_type', 'code');

			if (!config.openid.code_challenge_methods_supported) {
				cb = function(args) {
					const [ ] = args;
					return authorize(params);
				}
				break ok;
			}

			const code_verifier = base64url_encode(ab2bstr(crypto.getRandomValues(new Uint8Array(32))));

			switch (true) {
			case (config.openid.code_challenge_methods_supported || []).includes('S256'):
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
					return authorize(params, code_verifier);
				};
				break ok;
			case (config.openid.code_challenge_methods_supported || []).includes('plain'):
				params.append('code_challenge_method', 'plain');
				params.append('code_challenge', code_verifier);
				cb = function(args) {
					const [ ] = args;
					return authorize(params, code_verifier);
				}
				break ok;
			}
		}
		return Promise.reject(new Error('NYI'));
	case config.openid.grant_types_supported.includes('implicit'):
		switch (true) {
		case config.openid.response_types_supported.includes('token'):
			params.append('response_type', 'token');
			cb = function(args) {
				const [ ] = args;
				return authorize(params);
			}
			break ok;
		}
		return Promise.reject(new Error('NYI'));
	default:
		return Promise.reject(new Error('NYI'));
	}

	return Promise.all(args).then(cb);
}
function tokens(refresh) {
	return config.then(config => {
		if (__tokens && !refresh && performance.now() < __tokens._ts + (__tokens.expires_in * 1000))
			return __tokens;

		return untilOnline.then(() => {
			return _tokens(config, refresh).then(tokens => {
				if (!tokens.refresh_token && (__tokens || {}).refresh_token)
					tokens.refresh_token = __tokens.refresh_token;
				__tokens = tokens;
				if (!__tokens.refresh_token)
					console.info('no refresh token provided');
				// we use +2 so the demo sees the 401
				if (tokens.expires_in > (config.expires_in || -2) + 2) {
					__tokens.expires_in = config.expires_in + 2;
					setTimeout(function(){ __tokens.access_token = 'EXPIRED' }, config.expires_in * 1000);
				}
				return __tokens;
			});
		}).catch(error => {
			console.error('token', error);
			postMessage({ type: 'state', ok: false, data: { error: error.message } });
			return new Promise();	// stall
		});
	});
}

function _do_fetch(data, refresh) {
	return tokens(refresh).then(tokens => {
		data.data.options = data.data.options || {};
		data.data.options.headers = data.data.options.headers || new Headers();
		data.data.options.headers.set('authorization', [ tokens.token_type, tokens.access_token ].join(' '));

		return fetch(data.data.uri, data.data.options).then(
			response => {
				if (response.status == 401 && !refresh)
					return _do_fetch(data, true);
				return response;
			},
			reason => {
				return config.then(config => {
					if (config.cors_is_401 && !refresh)
						return _do_fetch(data, true);
					return Promise.reject(reason);
				});
			}
		);
	});
}

function do_revoke(data) {
	if (!__tokens)
		return postMessage({ id: data.id, ok: true });

	// https://tools.ietf.org/html/rfc7009
	return config.then(config => {
		if (!config.openid.revocation_endpoint)
			return postMessage({ id: data.id, ok: false });

		const headers = new Headers();
		if (config.client_secret)
			headers.append('authorization', 'Basic ' + btoa([ config.client_id, config.client_secret ].join(':')));

		const requests = [];
		if (performance.now() < __tokens._ts + (__tokens.expires_in * 1000)) {
			requests.push(
				fetch(config.openid.revocation_endpoint, {
					method: 'POST',
					headers: headers,
					body: (function(params){
						params.append('token', __tokens.access_token);
						params.append('token_type_hint', 'access_token');
						return params;
					})(new URLSearchParams())
				}).then(() => { __tokens.access_token = null })
			);
		}
		if (__tokens.refresh_token) {
			requests.push(
				fetch(config.openid.revocation_endpoint, {
					method: 'POST',
					headers: headers,
					body: (function(params){
						params.append('token', __tokens.refresh_token);
						params.append('token_type_hint', 'refresh_token');
						return params;
					})(new URLSearchParams())
				}).then(() => { __tokens.refresh_token = null })
			);
		}

		return Promise.all(requests).then(
			() => {
				__tokens = null;
				postMessage({ id: data.id, ok: true })
			},
			() => postMessage({ id: data.id, ok: false })
		);
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
			_do_fetch(data).then(response => response.json()).then(json => {
				postMessage({ id: data.id, ok: true, data: json });
			});
		});
	}).catch(error => {
		postMessage({ id: data.id, ok: false, data: { error: error.message } });
	});
}

function do_fetch(data) {
	let response = null;

	if (data.data.headers)
		data.data.headers = new Headers(data.data.headers);

	_do_fetch(data).then(response0 => {
		response = response0;
		return response0.blob();
	}).then(blob => {
		postMessage({ id: data.id, ok: true, data: {
			ok: response.ok,
			status: response.status,
			headers: Array.from(response.headers.entries()),
			body: blob
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
	case 'fetch':
		dispatch = do_fetch;
		break;
	case 'revoke':
		dispatch = do_revoke;
		break;
	case 'whoami':
		dispatch = do_whoami;
		break;
	default:
		if (!(event.data.id in pending))
			return console.warn('orphan', event.data);
		const promise = pending[event.data.id];
		delete pending[event.data.id];
		dispatch = event.data.ok ? promise.resolve : promise.reject;
	}

	dispatch(event.data);
};
