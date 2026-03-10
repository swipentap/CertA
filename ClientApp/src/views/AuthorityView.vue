<template>
  <div class="page-header d-print-none mb-3">
    <div class="container-xl">
      <h2 class="page-title">Certificate Authority</h2>
    </div>
  </div>
  <div v-if="loading" class="text-center py-4">Loading...</div>
  <div v-else-if="!ca" class="card">
    <div class="card-body">
      <div class="alert alert-warning">
        <h4 class="alert-title">No Certificate Authority Found</h4>
        <p class="mb-0">A Certificate Authority will be created automatically when you create your first certificate.</p>
      </div>
      <router-link to="/certificates/create" class="btn btn-primary">Create First Certificate</router-link>
    </div>
  </div>
  <div v-else>
    <div class="row">
      <div class="col-md-8">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">{{ ca.name }}</h3>
          </div>
          <div class="card-body">
            <dl class="row">
              <dt class="col-sm-3">Common Name</dt>
              <dd class="col-sm-9">{{ ca.commonName }}</dd>
              <dt class="col-sm-3">Organization</dt>
              <dd class="col-sm-9">{{ ca.organization }}</dd>
              <dt class="col-sm-3">Created</dt>
              <dd class="col-sm-9">{{ formatDate(ca.createdDate) }}</dd>
              <dt class="col-sm-3">Expiry</dt>
              <dd class="col-sm-9">{{ formatDate(ca.expiryDate) }}</dd>
              <dt class="col-sm-3">Status</dt>
              <dd class="col-sm-9">
                <span class="badge" :class="ca.isActive && !isExpired(ca) ? 'bg-success' : 'bg-warning'">
                  {{ ca.isActive && !isExpired(ca) ? 'Active' : 'Inactive/Expired' }}
                </span>
              </dd>
            </dl>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Download</h3>
          </div>
          <div class="card-body">
            <div class="d-grid gap-2">
              <a :href="downloadUrl('/Certificates/DownloadRootCA')" class="btn btn-primary" download>Root CA (PEM)</a>
              <a :href="downloadUrl('/Certificates/DownloadRootCAPfx')" class="btn btn-success" download>Root CA (PFX)</a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'
import { downloadUrl } from '../api'

const ca = ref(null)
const loading = ref(true)

function formatDate(d) {
  if (!d) return ''
  return new Date(d).toISOString().slice(0, 10)
}

function isExpired(c) {
  return new Date(c.expiryDate) < new Date()
}

onMounted(async () => {
  try {
    const res = await api.get('/api/ca')
    if (res.ok) ca.value = await res.json()
  } finally {
    loading.value = false
  }
})
</script>
