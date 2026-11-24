const base = '/api'

export function token() { return localStorage.getItem('token') || '' }
export function logout() {
  const current = token()
  fetch(base + '/auth/logout', {
    method: 'POST',
    headers: current ? {Authorization: `Bearer ${current}`} : {},
    credentials: 'same-origin',
    keepalive: true,
  }).catch(() => {})
  localStorage.removeItem('token')
  location.reload()
}

export async function api(path, options = {}) {
  const headers = {...(options.headers || {})}
  if (token()) headers.Authorization = `Bearer ${token()}`
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json'
  const method = (options.method || 'GET').toUpperCase()
  const attempts = (method === 'GET' || options.retry) ? 3 : 1
  let lastError
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetch(base + path, {credentials: 'same-origin', ...options, headers})
      // A 401 returned by the login endpoint is an ordinary validation error.
      // Only clear the current session when an authenticated request expires.
      if (response.status === 401 && path !== '/auth/login') {
        localStorage.removeItem('token')
        window.dispatchEvent(new Event('yunzhou-auth-expired'))
        throw new Error('登录已过期，请重新登录')
      }
      if ([502,503,504].includes(response.status) && attempt + 1 < attempts) {
        await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)))
        continue
      }
      if (!response.ok) {
        let detail = `请求失败 (${response.status})`
        let payload = null
        try {
          payload = await response.json()
          const raw = payload.detail
          if (Array.isArray(raw)) {
            detail = raw.map(item => item.msg || JSON.stringify(item)).join('；')
          } else if (raw && typeof raw === 'object') {
            detail = raw.message || raw.msg || JSON.stringify(raw)
          } else {
            detail = raw || detail
          }
        } catch {}
        const error = new Error(detail)
        error.status = response.status
        error.payload = payload
        throw error
      }
      return response.status === 204 ? null : response.json()
    } catch (error) {
      lastError = error
      if (attempt + 1 >= attempts || !(error instanceof TypeError)) throw error
      await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)))
    }
  }
  throw lastError || new Error('网络暂时不可用')
}

export async function login(username, password) {
  const result = await api('/auth/login', {method:'POST', body:JSON.stringify({username,password})})
  // Remove legacy browser-readable tokens after the server has issued the
  // HttpOnly session cookie.
  localStorage.removeItem('token')
  return result
}

