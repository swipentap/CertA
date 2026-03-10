<template>
  <div v-if="loading" class="text-center py-4">Loading...</div>
  <div v-else-if="!detail" class="alert alert-danger">Certificate not found.</div>
  <template v-else>
    <div class="page-header d-print-none mb-3">
      <div class="container-xl">
        <div class="row g-2 align-items-center">
          <div class="col">
            <h2 class="page-title">Certificate Details</h2>
            <div class="text-secondary">{{ detail.certificate.commonName }}</div>
          </div>
          <div class="col-auto">
            <router-link to="/certificates" class="btn btn-secondary">Back to Certificates</router-link>
          </div>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-md-8">
        <div class="card">
          <div class="card-body">
            <dl class="row">
              <dt class="col-sm-3">Common Name</dt>
              <dd class="col-sm-9">{{ detail.certificate.commonName }}</dd>
              <dt v-if="detail.certificate.subjectAlternativeNames" class="col-sm-3">Subject Alternative Names</dt>
              <dd v-if="detail.certificate.subjectAlternativeNames" class="col-sm-9">{{ detail.certificate.subjectAlternativeNames }}</dd>
              <dt class="col-sm-3">Serial Number</dt>
              <dd class="col-sm-9"><code>{{ detail.certificate.serialNumber }}</code></dd>
              <dt class="col-sm-3">Status</dt>
              <dd class="col-sm-9">
                <span class="badge" :class="detail.certificate.status === 1 ? 'bg-success' : 'bg-warning'">{{ statusLabel(detail.certificate.status) }}</span>
              </dd>
              <dt class="col-sm-3">Type</dt>
              <dd class="col-sm-9">{{ typeLabel(detail.certificate.type) }}</dd>
              <dt class="col-sm-3">Issued Date</dt>
              <dd class="col-sm-9">{{ formatDate(detail.certificate.issuedDate) }}</dd>
              <dt class="col-sm-3">Expiry Date</dt>
              <dd class="col-sm-9">{{ formatDate(detail.certificate.expiryDate) }}</dd>
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
              <a :href="downloadUrl('/Certificates/DownloadCertificate/' + detail.certificate.id)" class="btn btn-primary" download>Certificate (PEM)</a>
              <a :href="downloadUrl('/Certificates/DownloadPrivateKey/' + detail.certificate.id)" class="btn btn-danger" download>Private Key (PEM)</a>
              <a :href="downloadUrl('/Certificates/DownloadPublicKey/' + detail.certificate.id)" class="btn btn-info" download>Public Key (PEM)</a>
              <a :href="downloadUrl('/Certificates/DownloadHAProxy/' + detail.certificate.id)" class="btn btn-warning" download>HAProxy Format</a>
              <a :href="downloadUrl('/Certificates/DownloadPfx/' + detail.certificate.id)" class="btn btn-success" download>PFX/PKCS#12</a>
            </div>
            <small class="text-secondary d-block mt-2">PFX password: <code>password</code></small>
          </div>
        </div>
      </div>
    </div>
    <div class="row mt-3">
      <div class="col-12">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Certificate (PEM)</h3>
          </div>
          <div class="card-body">
            <pre class="bg-light p-3 rounded"><code>{{ detail.certificate.certificatePem }}</code></pre>
          </div>
        </div>
      </div>
    </div>
    <div class="row mt-3">
      <div class="col-12">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">HAProxy format</h3>
          </div>
          <div class="card-body">
            <pre class="bg-light p-3 rounded"><code>{{ detail.haproxyContent }}</code></pre>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api, downloadUrl } from '../api'

const route = useRoute()
const detail = ref(null)
const loading = ref(true)

function statusLabel(s) {
  const map = { 0: 'Pending', 1: 'Issued', 2: 'Revoked', 3: 'Expired' }
  return map[s] ?? 'Unknown'
}

function typeLabel(t) {
  const map = { 0: 'Server', 1: 'Client', 2: 'CodeSigning', 3: 'Email', 4: 'Wildcard' }
  return map[t] ?? 'Unknown'
}

function formatDate(d) {
  if (!d) return ''
  return new Date(d).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
}

onMounted(async () => {
  try {
    const res = await api.get('/api/certificates/' + route.params.id)
    if (res.ok) detail.value = await res.json()
  } finally {
    loading.value = false
  }
})
</script>
