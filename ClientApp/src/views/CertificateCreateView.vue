<template>
  <div class="page-header d-print-none mb-3">
    <div class="container-xl">
      <h2 class="page-title">New Certificate Request</h2>
    </div>
  </div>
  <div class="row">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">New Certificate Request</h3>
        </div>
        <div class="card-body">
          <form @submit.prevent="submit">
            <div v-if="error" class="alert alert-danger">{{ error }}</div>
            <div class="mb-3">
              <label class="form-label">Common Name (CN)</label>
              <input v-model="form.commonName" type="text" class="form-control" placeholder="e.g. example.com" required />
              <span class="form-hint">The primary domain name for this certificate.</span>
            </div>
            <div class="mb-3">
              <label class="form-label">Subject Alternative Names (SAN)</label>
              <input v-model="form.subjectAlternativeNames" type="text" class="form-control" placeholder="e.g. www.example.com, api.example.com" />
              <span class="form-hint">Additional domain names, separated by commas.</span>
            </div>
            <div class="mb-3">
              <label class="form-label">Certificate Type</label>
              <select v-model="form.type" class="form-select">
                <option :value="0">Server</option>
                <option :value="1">Client</option>
                <option :value="2">CodeSigning</option>
                <option :value="3">Email</option>
                <option :value="4">Wildcard</option>
              </select>
            </div>
            <div class="d-flex justify-content-between">
              <router-link to="/certificates" class="btn btn-secondary">Back to Certificates</router-link>
              <button type="submit" class="btn btn-primary" :disabled="loading">Create Request</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'

const router = useRouter()
const form = reactive({
  commonName: '',
  subjectAlternativeNames: '',
  type: 0,
})
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    const res = await api.post('/api/certificates', {
      commonName: form.commonName,
      subjectAlternativeNames: form.subjectAlternativeNames || null,
      type: form.type,
    })
    if (res.ok) {
      const data = await res.json()
      router.push('/certificates/' + data.id)
      return
    }
    const data = await res.json().catch(() => ({}))
    error.value = data.message || data.title || 'Create failed.'
  } catch (e) {
    error.value = e.message || 'Create failed.'
  } finally {
    loading.value = false
  }
}
</script>
