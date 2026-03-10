<template>
  <div class="page-header d-print-none mb-3">
    <div class="container-xl">
      <div class="row g-2 align-items-center">
        <div class="col">
          <h2 class="page-title">Certificates</h2>
        </div>
        <div class="col-auto">
          <router-link to="/certificates/create" class="btn btn-primary">New Certificate</router-link>
        </div>
      </div>
    </div>
  </div>
  <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-danger'">{{ message }}</div>
  <div v-if="loading" class="text-center py-4">Loading...</div>
  <div v-else-if="!list?.length" class="card">
    <div class="card-body text-center py-5">
      <p class="text-secondary">No certificates found. Get started by creating your first certificate.</p>
      <router-link to="/certificates/create" class="btn btn-primary">Create Certificate</router-link>
    </div>
  </div>
  <div v-else class="card">
    <div class="table-responsive">
      <table class="table table-vcenter card-table table-striped">
        <thead>
          <tr>
            <th>Common Name</th>
            <th>Serial Number</th>
            <th>Status</th>
            <th>Issued</th>
            <th>Expiry</th>
            <th class="w-1">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="cert in list" :key="cert.id">
            <td>
              <router-link :to="'/certificates/' + cert.id">{{ cert.commonName }}</router-link>
            </td>
            <td><code class="text-sm">{{ cert.serialNumber }}</code></td>
            <td>
              <span class="badge" :class="cert.status === 1 ? 'bg-success' : 'bg-warning'">{{ statusLabel(cert.status) }}</span>
            </td>
            <td>{{ formatDate(cert.issuedDate) }}</td>
            <td>{{ formatDate(cert.expiryDate) }}</td>
            <td>
              <router-link :to="'/certificates/' + cert.id" class="btn btn-sm btn-outline-primary me-1">View</router-link>
              <button type="button" class="btn btn-sm btn-outline-danger" :disabled="deleting === cert.id" @click="confirmDelete(cert)">Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'

const list = ref([])
const loading = ref(true)
const message = ref('')
const messageType = ref('success')
const deleting = ref(null)

function statusLabel(status) {
  const map = { 0: 'Pending', 1: 'Issued', 2: 'Revoked', 3: 'Expired' }
  return map[status] ?? 'Unknown'
}

function formatDate(d) {
  if (!d) return ''
  const date = new Date(d)
  return date.toISOString().slice(0, 10)
}

async function load() {
  loading.value = true
  try {
    const res = await api.get('/api/certificates')
    if (res.ok) list.value = await res.json()
  } finally {
    loading.value = false
  }
}

async function confirmDelete(cert) {
  if (!confirm('Are you sure you want to delete this certificate? This action cannot be undone.')) return
  deleting.value = cert.id
  try {
    const res = await api.delete('/api/certificates/' + cert.id)
    if (res.ok || res.redirected) {
      message.value = 'Certificate deleted.'
      messageType.value = 'success'
      await load()
    } else {
      message.value = 'Delete failed.'
      messageType.value = 'danger'
    }
  } catch {
    message.value = 'Delete failed.'
    messageType.value = 'danger'
  } finally {
    deleting.value = null
  }
}

onMounted(load)
</script>
