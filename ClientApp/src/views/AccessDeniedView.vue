<template>
  <div class="page page-center">
    <div class="container container-tight py-4">
      <div class="empty">
        <div class="empty-header">403</div>
        <p class="empty-title">Access denied</p>
        <p class="empty-subtitle text-secondary">{{ message }}</p>
        <div class="empty-action">
          <form method="post" action="/Account/Logout" class="d-inline">
            <input type="hidden" name="__RequestVerificationToken" :value="antiforgeryToken" />
            <button type="submit" class="btn btn-primary" :disabled="!antiforgeryToken">Logout</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const antiforgeryToken = ref('')
const message = computed(() => route.query.message || 'Access requires the admin role.')

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
