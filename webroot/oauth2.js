export const OAuth2 = (function() {
	const pending = {};

	let worker = null;
	let authorize_callback = null;

	function authorize(data) {
		new Promise((resolve, reject) => {
			authorize_callback({ resolve: resolve, reject: reject });
		}).then((promise) => {
			return new Promise((resolve, reject) => {
				pending[data.id] = { resolve: resolve, reject: reject };

				const source = open(data.data.uri, '_blank');

				const cb = (event) => {
					if (event.source != source) return;

					if (typeof event.data != 'object')
						return console.warn('orphan', event.data);

//					console.info(e);

					if (event.data.id == data.id)
						worker.postMessage(event.data)
					else if (event.data.id == null) {
						console.warn('failed', event.data.data);
						reject(event.data.data);
					} else {
						console.error('mismatch', event.data);
						reject(event.data);
					}

					source.close();

					removeEventListener('message', cb);
				}

				addEventListener('message', cb);
			}).then(data => {
				promise.resolve({ ok: true });
			}).catch(error => {
				promise.reject({ ok: false, error: error });
			});
		});
	}

	function send(data) {
		// https://stackoverflow.com/a/2117523
		function uuidv4() {
			return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
				(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
			);
		}

		return new Promise((resolve, reject) => {
			data.id = uuidv4();

			pending[data.id] = { resolve: resolve, reject: reject };

			worker.postMessage(data);
		});
	}

	function recv(event) {
//		console.info(event.data);

		switch (event.data.type) {
		case 'authorize':
			authorize(event.data);
			break;
		default:
			if (!(event.data.id in pending))
				return console.warn('orphan', event.data);
			const promise = pending[event.data.id];
			delete pending[event.data.id];
			if (event.data.ok)
				promise.resolve(event.data.data)
			else
				promise.reject(event.data.data);
		}
	}

	function OAuth2(config) {
		if (typeof config != 'object') throw new Error('missing configuration object');
		if (typeof config.client_id != 'string') throw new Error("missing 'client_id' string");
		if (!config.redirect_uri) config.redirect_uri = '/oauth2-redirect.html';
		if (typeof config.redirect_uri != 'string') throw new Error("missing 'redirect_uri' string");
		if (!(typeof config.discovery_endpoint == 'string' || typeof config.discovery_overlay == 'object')) throw new Error("missing/invalid 'discovery_{endpoint,overlay}'");
		if (typeof config.authorize_callback != 'function') throw new Error("missing 'authorize_callback' function");

		authorize_callback = config.authorize_callback;
		delete config.authorize_callback;

		worker = new Worker('oauth2-worker.js');
		worker.onmessage = recv;
		worker.postMessage({ type: '_config', data: config });
	}

	OAuth2.prototype.terminate = function() {
		return this.revoke().then(
			() => worker.terminate(),
			() => worker.terminate()
		);
	};

	OAuth2.prototype.fetch = function(uri, options) {
		options = options || {}

		switch (true) {
		case options.headers === undefined:
		case options.headers instanceof Headers:
			break;
		case options.headers instanceof Array:
		case options.headers instanceof Object:
			options.headers = new Headers(options.headers);
			break;
		default:
			return Promise.reject(new Error("unsupported headers representation"));
		}
		if (options.headers) {
			if (options.headers.has('authorization'))
				return Promise.reject(new Error("contains 'authorization' header"));
			options.headers = Array.from(options.headers.entries());
		}

		return send({ type: 'fetch', data: { uri: uri, options: options } }).then(response => {
			response.headers = new Headers(response.headers);
			return response;
		});
	};

	OAuth2.prototype.revoke = function() {
		return send({ type: 'revoke' });
	};

	OAuth2.prototype.whoami = function(type) {
		return send({ type: 'whoami', data: { type: type } });
	};

	return OAuth2;
}).call(this);
