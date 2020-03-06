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

let config = null;
function init(data) {
	config = new Promise((resolve, reject) => {
		function validate(discovery) {
			discovery = Object.keys(data.data.discovery_overlay || {}).reduce((a, k) => {
				a[k] = data.data.discovery_overlay[k];
				return a;
			}, discovery);

			// https://tools.ietf.org/html/rfc8414
			discovery.grant_types_supported = discovery.grant_types_supported || [ 'authorization_code', 'implicit' ];

			if (!discovery.grant_types_supported.includes('authorization_code'))
				throw new Error("'authorization_code' grant not supported");

			outer: switch (true) {
			case discovery.response_types_supported.includes('code'):
				switch (true) {
				case (discovery.code_challenge_methods_supported || []).includes('S256'):
				case (discovery.code_challenge_methods_supported || []).includes('plain'):
					break outer;
				}
				// FALLTHROUGH
			case discovery.response_types_supported.includes('token'):
				break outer;
			default:
				throw new Error("neither 'code' or 'token' response type supported");
			}

			if (data.data.scopes && discovery.scopes_supported) {
				const overlap = data.data.scopes.filter(scope => discovery.scopes_supported.includes(scope));
				if (overlap.length < data.data.scopes.length) throw new Error('not all requested scopes are available');
			}

			data.data.openid = discovery;
			resolve(data.data);
		}

		if (!data.data.discovery_endpoint)
			return validate({});

		return fetch(data.data.discovery_endpoint + '/.well-known/openid-configuration').then(
			response => {
				if (!response.ok) throw new Error(response.statusText);
				return response.json();
			}
		).then(
			discovery => {
				validate(discovery);
			}
		).catch(
			error => {
				reject(null);
				console.error('init', error.message);
				throw new Error('init: ' + error);
			}
		);
	});
}

let _tokens = null;
function tokens(toks) {
	if (toks && _tokens) _tokens = null;

	_tokens = _tokens || config.then(config => { return new Promise((resolve, reject) => {
		function request(params) {
			params.append('client_id', config.client_id);

			return fetch(config.openid.token_endpoint, {
				method: 'POST',
				body: params
			}).then(
				response => {
					if (toks && response.status == 401)
						return tokens({});
					if (!response.ok) throw new error(response.statustext);
					return response.json();
				}
			);
		}

		function authorize(params0, code_verifier) {
			const id = uuidv4();

			params0.append('redirect_uri', location.origin + config.redirect_uri),
			params0.append('state', id);

			if (config.scopes)
				params0.append('scope', config.scopes.join(' '));

			const redirect = new Promise((resolve, reject) => {
				pending[id] = { resolve: resolve, reject: reject };
			}).then(
				redirect => {
					if (redirect.data.access_token) {
						redirect.data._ts = performance.now();
						resolve(redirect.data);
						postMessage({ id: id, ok: true });
						return;
					}

					const params = new URLSearchParams();

					params.append('grant_type', 'authorization_code');
					params.append('redirect_uri', location.origin + config.redirect_uri);
					params.append('code', redirect.data.code);
					if (params0.has('code_challenge'))
						params.append('code_verifier', code_verifier);

					return request(params).then(
						json => {
							json._ts = performance.now();
							resolve(json);
							postMessage({ id: id, ok: true });
						}
					).catch(
						error => {
							console.error('redirect', error.message);
							reject(null);
							postMessage({ id: id, ok: false, data: { error: error.message } });
						}
					);

				}
			);

			postMessage({ type: 'authorize', id: id, data: {
				uri: config.openid.authorization_endpoint + '?' + params0.toString()
			}});

			return redirect;
		}

		const args = [];
		let cb = null;

		const params = new URLSearchParams();

		params.append('client_id', config.client_id);

		switch (true) {
		case !!(toks || {}).refresh_token:
			params.append('grant_type', 'refresh_token');
			params.append('refresh_token', toks.refresh_token);
			cb = function(args) {
				const [ ] = args;
				request(params);
			}
			break;
		case config.openid.response_types_supported.includes('code'):
			const code_verifier = base64url_encode(ab2bstr(crypto.getRandomValues(new Uint8Array(32))));

			params.append('response_type', 'code');

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
					authorize(params, code_verifier);
				};
				break;
			case (config.openid.code_challenge_methods_supported || []).includes('plain'):
				params.append('code_challenge_method', 'plain');
				params.append('code_challenge', code_verifier);
				cb = function(args) {
					const [ ] = args;
					authorize(params, code_verifier);
				}
				break;
			default:
				console.error('NYI');
				throw new Error('NYI');
			}
			break;
		case config.openid.response_types_supported.includes('token'):
			params.append('response_type', 'token');
			cb = function(args) {
				const [ ] = args;
				authorize(params);
			}
			break;
		}

		return Promise.all(args).then(cb);
	})});

	return _tokens;
}

function _do_fetch(data, toks) {
	return tokens(toks).then(toks => {
		data.data.options = data.data.options || {};
		data.data.options.headers = data.data.options.headers || {};
		data.data.options.headers['authorization'] = [ toks.token_type, toks.access_token ].join(' ');

		return fetch(data.data.uri, data.data.options).then(
			response => {
				if (response.status == 401)
					return do_fetch(data, toks);
				return response;
			},
			error => {
				postMessage({ id: data.id, ok: false, data: { error: error } });
			}
		).catch(error => {
			postMessage({ id: data.id, ok: false, data: { error: error.message } });
		});
	});
}

function do_whoami(data) {
	tokens().then(tokens => {
		if (tokens.id_token) {
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
	});
}

onmessage = function(e) {
	function cb(){
		let dispatch = null;

		switch (e.data.type) {
		case 'init':
			dispatch = init;
			break;
		case 'whoami':
			dispatch = do_whoami;
			break;
		case 'fetch':
			dispatch = do_fetch;
			break;
		default:
			if (!(e.data.id in pending))
				return console.warn('orphan', e.data);
			const promise = pending[e.data.id];
			delete pending[e.data.id];
			dispatch = e.data.ok ? promise.resolve : promise.reject;
		}

		dispatch(e.data);
	};

//	console.info(e.data);

	if (config)
		config.then(cb)
	else if (e.data.type == 'init')
		cb()
	else {
		console.error('uninit');
		throw new Error('uninit');
	}
}
