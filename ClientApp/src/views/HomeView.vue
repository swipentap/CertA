<template>
  <div class="page-header d-print-none mb-3">
    <div class="container-xl">
      <div class="row g-2 align-items-center">
        <div class="col">
          <h2 class="page-title">CertA Certification Authority</h2>
          <div class="text-secondary mt-1">Manage your certificates and certificate authority</div>
        </div>
      </div>
    </div>
  </div>
  <div class="row row-deck row-cards">
    <div class="col-md-6">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Quick Actions</h3>
        </div>
        <div class="card-body">
          <div class="d-grid gap-2">
            <router-link to="/certificates/create" class="btn btn-primary">Create New Certificate</router-link>
            <router-link to="/certificates" class="btn btn-outline-primary">View All Certificates</router-link>
            <router-link to="/certificates/authority" class="btn btn-outline-success">Certificate Authority</router-link>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Statistics</h3>
        </div>
        <div class="card-body">
          <div class="row text-center">
            <div class="col-6">
              <h3 class="text-primary">{{ dashboard?.totalCertificates ?? 0 }}</h3>
              <small class="text-secondary">Total Certificates</small>
            </div>
            <div class="col-6">
              <h3 :class="dashboard?.activeCA ? 'text-success' : 'text-warning'">{{ dashboard?.activeCA ? '1' : '0' }}</h3>
              <small class="text-secondary">Active CA</small>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="row row-deck row-cards mt-3">
    <div class="col-md-6">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Recent Certificates</h3>
        </div>
        <div class="card-body">
          <div v-if="dashboard?.recentCertificates?.length" class="list-group list-group-flush">
            <div
              v-for="cert in dashboard.recentCertificates"
              :key="cert.id"
              class="list-group-item d-flex justify-content-between align-items-center"
            >
              <div>
                <router-link :to="'/certificates/' + cert.id">{{ cert.commonName }}</router-link>
                <br />
                <small class="text-secondary">{{ cert.type }} Certificate</small>
              </div>
              <span class="badge" :class="cert.status === 1 ? 'bg-success' : 'bg-warning'">{{ statusLabel(cert.status) }}</span>
            </div>
          </div>
          <div v-else class="text-center text-secondary py-4">
            <p class="mb-2">No certificates yet</p>
            <router-link to="/certificates/create" class="btn btn-sm btn-primary">Create First Certificate</router-link>
          </div>
          <div class="mt-3">
            <router-link to="/certificates" class="btn btn-sm btn-outline-primary">View All</router-link>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Getting Started</h3>
        </div>
        <div class="card-body">
          <ol class="mb-0">
            <li>Download and install the <router-link to="/certificates/authority">Root CA Certificate</router-link></li>
            <li>Create certificates for your domains</li>
            <li>Download certificates and keys as needed</li>
            <li>Install certificates on your servers</li>
          </ol>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'

const dashboard = ref(null)

function statusLabel(status) {
  const map = { 0: 'Pending', 1: 'Issued', 2: 'Revoked', 3: 'Expired' }
  return map[status] ?? 'Unknown'
}

onMounted(async () => {
  const res = await api.get('/api/dashboard')
  if (res.ok) dashboard.value = await res.json()
})
</script>
