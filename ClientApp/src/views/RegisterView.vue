<template>
  <div class="page page-center">
    <div class="container container-tight py-4">
      <div class="text-center mb-4">
        <a href="/" class="navbar-brand navbar-brand-autodark">CertA</a>
      </div>
      <div class="card card-md">
        <div class="card-body">
          <h2 class="card-title text-center mb-4">Register</h2>
          <form @submit.prevent="submit">
            <div v-if="error" class="alert alert-danger">{{ error }}</div>
            <div class="mb-3">
              <label class="form-label">First Name</label>
              <input v-model="firstName" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label class="form-label">Last Name</label>
              <input v-model="lastName" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input v-model="email" type="email" class="form-control" required />
            </div>
            <div class="mb-3">
              <label class="form-label">Organization</label>
              <input v-model="organization" type="text" class="form-control" />
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input v-model="password" type="password" class="form-control" required minlength="6" />
            </div>
            <div class="mb-3">
              <label class="form-label">Confirm Password</label>
              <input v-model="confirmPassword" type="password" class="form-control" required />
              <span v-if="confirmPassword && password !== confirmPassword" class="text-danger small">Passwords do not match.</span>
            </div>
            <div class="form-footer">
              <button type="submit" class="btn btn-primary w-100" :disabled="loading || (!!confirmPassword && password !== confirmPassword)">Register</button>
            </div>
          </form>
          <div class="text-center text-secondary mt-3">
            <router-link to="/login">Already have an account? Login</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { api } from '../api'

const router = useRouter()
const auth = useAuthStore()

const firstName = ref('')
const lastName = ref('')
const email = ref('')
const organization = ref('')
const password = ref('')
const confirmPassword = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  if (password.value !== confirmPassword.value) return
  error.value = ''
  loading.value = true
  try {
    const res = await api.post('/api/account/register', {
      firstName: firstName.value,
      lastName: lastName.value,
      email: email.value,
      organization: organization.value || null,
      password: password.value,
      confirmPassword: confirmPassword.value,
    })
    if (res.ok) {
      auth.clearUser()
      await auth.fetchUser()
      router.push('/')
      return
    }
    const data = await res.json().catch(() => ({}))
    error.value = data.message || data.title || 'Registration failed.'
  } catch (e) {
    error.value = e.message || 'Registration failed.'
  } finally {
    loading.value = false
  }
}
</script>
