function qs2o(s) {
    s = s.split(/[#?]/)[1];
    return s.split('&').reduce((a, p) => {
        const m = p.split('=');
        a[decodeURIComponent(m[0])] = decodeURIComponent(m[1]);
        return a;
    }, {});
}

const o = qs2o(location.hash.length ? location.hash : location.search);

if (o.state)
    opener.postMessage({ id: o.state, ok: true, data: o })
else
    opener.postMessage({ id: null, ok: false, data: { error: o.error, description: o.error_description, location: { search: location.search, hash: location.hash } } });
