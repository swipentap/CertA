<template>
  <div class="page">
    <header class="navbar navbar-expand-md navbar-light d-print-none">
      <div class="container-xl">
        <h1 class="navbar-brand navbar-brand-autodark d-none-navbar-horizontal pe-0 pe-md-3">
          <router-link to="/" class="text-decoration-none">
            <span class="navbar-brand-image me-2">
              <svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-shield-lock" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                <path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" />
                <path d="M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" />
                <path d="M12 12l0 2.5" />
              </svg>
            </span>
            CertA
          </router-link>
        </h1>
        <div class="navbar-nav flex-row order-md-last">
          <form method="post" action="/Account/Logout" class="d-inline nav-item">
            <input type="hidden" name="__RequestVerificationToken" :value="antiforgeryToken" />
            <button type="submit" class="btn btn-link nav-link py-2" :disabled="!antiforgeryToken">Logout</button>
          </form>
          <div class="nav-item dropdown">
            <a href="#" class="nav-link d-flex lh-1 text-reset p-0" @click.prevent="userMenuOpen = !userMenuOpen">
              <span class="avatar avatar-sm">{{ avatarLetter }}</span>
              <div class="d-none d-xl-block ps-2">
                <div>{{ auth.userName }}</div>
              </div>
            </a>
            <div v-show="userMenuOpen" class="dropdown-menu dropdown-menu-end dropdown-menu-arrow show">
              <router-link to="/account/profile" class="dropdown-item" @click="userMenuOpen = false">Profile</router-link>
              <div class="dropdown-divider"></div>
              <form method="post" action="/Account/Logout" class="d-inline">
                <input type="hidden" name="__RequestVerificationToken" :value="antiforgeryToken" />
                <button type="submit" class="dropdown-item" :disabled="!antiforgeryToken">Logout</button>
              </form>
            </div>
          </div>
        </div>
        <div class="collapse navbar-collapse" id="navbar-menu">
          <ul class="navbar-nav pt-lg-3">
            <li class="nav-item">
              <router-link to="/" class="nav-link">
                <span class="nav-link-icon">
                  <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l-2 0l9 -9l9 9l-2 0" /><path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7" /></svg>
                </span>
                <span class="nav-link-title">Home</span>
              </router-link>
            </li>
            <li class="nav-item">
              <router-link to="/certificates" class="nav-link">
                <span class="nav-link-icon">
                  <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" /><path d="M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /></svg>
                </span>
                <span class="nav-link-title">My Certificates</span>
              </router-link>
            </li>
            <li class="nav-item">
              <router-link to="/certificates/authority" class="nav-link">
                <span class="nav-link-icon">
                  <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" /></svg>
                </span>
                <span class="nav-link-title">Certificate Authority</span>
              </router-link>
            </li>
            <li class="nav-item">
              <router-link to="/privacy" class="nav-link">
                <span class="nav-link-title">Privacy</span>
              </router-link>
            </li>
          </ul>
        </div>
      </div>
    </header>
    <div class="page-wrapper">
      <div class="page-body">
        <div class="container-xl">
          <router-view />
        </div>
      </div>
      <footer class="footer footer-transparent d-print-none">
        <div class="container-xl">
          &copy; {{ new Date().getFullYear() }} CertA — <router-link to="/privacy">Privacy</router-link>
        </div>
      </footer>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const avatarLetter = computed(() => (auth.userName || 'A').charAt(0).toUpperCase())
const antiforgeryToken = ref('')
const userMenuOpen = ref(false)

onMounted(async () => {
  try {
    const res = await fetch('/api/antiforgery', { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      antiforgeryToken.value = data.token || ''
    }
  } catch {}
})

</script>
