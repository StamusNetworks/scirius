/* eslint-disable */
export const parseUrl = () => {
  const params = {};
  (new URLSearchParams(document.location.search)).forEach((d, e) => {
    let a = decodeURIComponent(e);
    const c = decodeURIComponent(d);
    if (a.endsWith('[]')) {
      a = a.replace("[]", ""), params[a] || (params[a] = []), params[a].push(c)
    } else {
      let b = a.match(/\[([a-z0-9_\/\s,.-])+\]$/g);
      b ? (a = a.replace(b, ""), b = b[0].replace("[", "").replace("]", ""), params[a] || (params[a] = []), params[a][b] = c) : params[a] = c
    }
  })
  return params
}
