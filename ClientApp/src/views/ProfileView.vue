<template>
  <div class="page-header d-print-none mb-3">
    <div class="container-xl">
      <h2 class="page-title">Profile</h2>
    </div>
  </div>
  <div class="row">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Edit Profile</h3>
        </div>
        <div class="card-body">
          <form @submit.prevent="submit">
            <div v-if="success" class="alert alert-success">{{ success }}</div>
            <div v-if="error" class="alert alert-danger">{{ error }}</div>
            <div class="mb-3">
              <label class="form-label">First Name</label>
              <input v-model="form.firstName" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label class="form-label">Last Name</label>
              <input v-model="form.lastName" type="text" class="form-control" required />
            </div>
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input v-model="form.email" type="email" class="form-control" disabled />
              <small class="text-secondary">Email cannot be changed.</small>
            </div>
            <div class="mb-3">
              <label class="form-label">Organization</label>
              <input v-model="form.organization" type="text" class="form-control" />
            </div>
            <button type="submit" class="btn btn-primary" :disabled="loading">Save</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api } from '../api'

const form = reactive({ firstName: '', lastName: '', email: '', organization: '' })
const success = ref('')
const error = ref('')
const loading = ref(false)

onMounted(async () => {
  const res = await api.get('/api/account/profile')
  if (res.ok) {
    const data = await res.json()
    form.firstName = data.firstName ?? ''
    form.lastName = data.lastName ?? ''
    form.email = data.email ?? ''
    form.organization = data.organization ?? ''
  }
})

async function submit() {
  success.value = ''
  error.value = ''
  loading.value = true
  try {
    const res = await api.put('/api/account/profile', form)
    if (res.ok) {
      success.value = 'Profile updated successfully.'
      return
    }
    const data = await res.json().catch(() => ({}))
    error.value = data.message || data.title || 'Update failed.'
  } catch (e) {
    error.value = e.message || 'Update failed.'
  } finally {
    loading.value = false
  }
}
</script>
