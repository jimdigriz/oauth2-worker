(function(){
  function qs2o(s) {
      s = s.split(/[#?]/)[1];
      return s.split('&').reduce((a, p) => {
          const m = p.split('=');
          a[decodeURIComponent(m[0])] = decodeURIComponent(m[1]);
          return a;
      }, {});
  }

  const ls = location.search, lh = location.hash;

  location.hash = '';
  history.replaceState(null, '', '/');

  const o = qs2o(lh.length ? lh : ls);

  const data = {
    id: o.state || null,
    ok: !!o.state,
    data: o
  };

  if (!data.ok) {
    data.data = {
      error: o.error,
      description: o.error_description,
      location: {
        search: location.search,
        hash: location.hash
      }
    };
  }

  opener.postMessage(data);
}).call(this);
