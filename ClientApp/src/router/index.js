import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/access-denied',
    name: 'AccessDenied',
    component: () => import('../views/AccessDeniedView.vue'),
  },
  {
    path: '/',
    component: () => import('../layouts/AppLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: '', name: 'Home', component: () => import('../views/HomeView.vue') },
      { path: 'certificates', name: 'Certificates', component: () => import('../views/CertificatesView.vue') },
      { path: 'certificates/create', name: 'CreateCertificate', component: () => import('../views/CertificateCreateView.vue') },
      { path: 'certificates/:id', name: 'CertificateDetails', component: () => import('../views/CertificateDetailsView.vue') },
      { path: 'certificates/authority', name: 'Authority', component: () => import('../views/AuthorityView.vue') },
      { path: 'account/profile', name: 'Profile', component: () => import('../views/ProfileView.vue') },
      { path: 'privacy', name: 'Privacy', component: () => import('../views/PrivacyView.vue') },
    ],
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/LoginView.vue'),
    meta: { guest: true },
  },
  {
    path: '/register',
    name: 'Register',
    component: () => import('../views/RegisterView.vue'),
    meta: { guest: true },
  },
]

const router = createRouter({
  history: createWebHistory('/'),
  routes,
})

router.beforeEach(async (to, _from, next) => {
  const auth = useAuthStore()
  await auth.fetchUser()
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    if (auth.oauth2AuthorizeUrl) {
      window.location.href = auth.oauth2AuthorizeUrl + '?returnUrl=' + encodeURIComponent(to.fullPath)
      return
    }
    next({ name: 'Login', query: { returnUrl: to.fullPath } })
    return
  }
  if (to.meta.guest && auth.isAuthenticated) {
    next({ name: 'Home' })
    return
  }
  next()
})

export default router
