const base = ''

export const api = {
  async request(path, options = {}) {
    const url = path.startsWith('http') ? path : base + path
    const res = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })
    return res
  },
  get(path) {
    return this.request(path, { method: 'GET' })
  },
  post(path, body) {
    return this.request(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined })
  },
  put(path, body) {
    return this.request(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined })
  },
  delete(path) {
    return this.request(path, { method: 'DELETE' })
  },
}

export function downloadUrl(path) {
  return base + path
}
