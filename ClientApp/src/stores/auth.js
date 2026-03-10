import { defineStore } from 'pinia'
import { api } from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    oauth2Enabled: false,
    oauth2UseEmbedded: false,
    _fetched: false,
  }),
  getters: {
    isAuthenticated: (state) => !!state.user,
    userName: (state) => state.user?.name ?? state.user?.email ?? 'Account',
    /** When true, OAuth2 uses embedded OpenIddict (show form). When false and oauth2Enabled, use Keycloak (redirect). */
    oauth2UseEmbedded: (state) => state.oauth2UseEmbedded,
    /** URL for SPA-initiated OAuth2 redirect. Use when oauth2Enabled && !oauth2UseEmbedded. */
    oauth2AuthorizeUrl: (state) => state.oauth2Enabled && !state.oauth2UseEmbedded ? '/api/auth/authorize' : null,
  },
  actions: {
    async fetchUser() {
      if (this._fetched) return
      this._fetched = true
      const isRoot = typeof window !== 'undefined' && (window.location.pathname === '/' || window.location.pathname === '')
      if (isRoot) {
        await new Promise((r) => setTimeout(r, 300))
      }
      const fetchOnce = async () => {
        try {
          const res = await api.get('/api/me')
          if (res.ok) {
            const data = await res.json()
            this.user = data.user
            this.oauth2Enabled = data.oauth2Enabled === true
            this.oauth2UseEmbedded = data.oauth2UseEmbedded === true
          } else {
            this.user = null
            const data = await res.json().catch(() => ({}))
            this.oauth2Enabled = data.oauth2Enabled === true
            this.oauth2UseEmbedded = data.oauth2UseEmbedded === true
          }
        } catch {
          this.user = null
        }
      }
      await fetchOnce()
      if (this.user == null && this.oauth2Enabled) {
        for (let i = 0; i < 3 && this.user == null; i++) {
          await new Promise((r) => setTimeout(r, 600))
          await fetchOnce()
        }
      }
    },
    clearUser() {
      this.user = null
      this._fetched = false
    },
  },
})
