<template>
  <div v-if="redirecting" class="page page-center">
    <div class="container container-tight py-4 text-center">
      <p class="text-secondary">Redirecting to sign in…</p>
    </div>
  </div>
  <div v-else class="page page-center">
    <div class="container container-tight py-4">
      <div class="text-center mb-4">
        <a href="/" class="navbar-brand navbar-brand-autodark">
          <span class="navbar-brand-image me-2">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-shield-lock" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
              <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
              <path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" />
              <path d="M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" />
              <path d="M12 12l0 2.5" />
            </svg>
          </span>
          CertA
        </a>
      </div>
      <div class="card card-md">
        <div class="card-body">
          <h2 class="card-title text-center mb-4">Login</h2>
          <form @submit.prevent="submitLogin">
            <input type="hidden" name="__RequestVerificationToken" :value="antiforgeryToken" />
            <input type="hidden" name="ReturnUrl" :value="returnUrl" />
            <div v-if="error" class="alert alert-danger">{{ error }}</div>
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input
                v-model="email"
                type="email"
                name="Email"
                class="form-control"
                placeholder="Enter your email"
                required
              />
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input
                v-model="password"
                type="password"
                name="Password"
                class="form-control"
                placeholder="Enter your password"
                required
              />
            </div>
            <div class="mb-3">
              <label class="form-check">
                <input v-model="rememberMe" type="checkbox" name="RememberMe" class="form-check-input" />
                <span class="form-check-label">Remember me</span>
              </label>
            </div>
            <div class="form-footer">
              <button type="submit" class="btn btn-primary w-100" :disabled="!antiforgeryToken || submitting">Login</button>
            </div>
          </form>
          <div class="hr-text">or</div>
          <div class="text-center text-secondary">
            <p class="mb-0">Don't have an account?</p>
            <router-link to="/register" class="btn btn-outline-secondary mt-2">Register</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const auth = useAuthStore()

const redirecting = ref(false)
const email = ref('')
const password = ref('')
const rememberMe = ref(false)
const error = ref('')
const antiforgeryToken = ref('')
const submitting = ref(false)

const returnUrl = computed(() => route.query.returnUrl || route.query.ReturnUrl || '/')

async function submitLogin() {
  if (!antiforgeryToken.value) return
  error.value = ''
  submitting.value = true
  try {
    const body = new URLSearchParams({
      __RequestVerificationToken: antiforgeryToken.value,
      Email: email.value,
      Password: password.value,
      RememberMe: rememberMe.value,
      ReturnUrl: returnUrl.value
    })
    const res = await fetch('/Account/Login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-XSRF-TOKEN': antiforgeryToken.value
      },
      body: body.toString(),
      redirect: 'follow'
    })
    if (res.redirected) {
      window.location.href = res.url
      return
    }
    if (!res.ok) {
      error.value = 'Login failed.'
      return
    }
    const text = await res.text()
    if (text.includes('error=')) {
      const match = text.match(/error=([^&"']+)/)
      error.value = match ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : 'Login failed.'
      return
    }
    window.location.href = returnUrl.value || '/'
  } catch (e) {
    error.value = 'Network error. Please try again.'
  } finally {
    submitting.value = false
  }
}

function getReturnUrl() {
  return route.query.returnUrl || route.query.ReturnUrl || '/'
}

onMounted(async () => {
  if (route.query.error) {
    error.value = decodeURIComponent(route.query.error) || 'Login failed.'
  }
  if (route.query.form === '1') {
    // Server sent us here from /api/auth/authorize (embedded mode) – show form, do not redirect
  } else if (auth.oauth2AuthorizeUrl) {
    redirecting.value = true
    const returnUrl = getReturnUrl()
    window.location.href = auth.oauth2AuthorizeUrl + '?returnUrl=' + encodeURIComponent(returnUrl)
    return
  }
  try {
    const res = await fetch('/api/antiforgery', { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      antiforgeryToken.value = data.token || ''
    }
  } catch {}
})
</script>
