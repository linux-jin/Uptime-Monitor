<template>
  <transition enter-active-class="transition duration-500 ease-out" enter-from-class="opacity-0 lg:scale-95 translate-y-4" enter-to-class="opacity-100 scale-100 translate-y-0">
    <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <!-- Animated Background Blur & Gradient -->
      <div class="absolute inset-0 bg-slate-950/80 backdrop-blur-md"></div>
      
      <!-- Modal Container -->
      <div class="relative w-full max-w-sm rounded-2xl overflow-hidden bg-slate-900/95 border border-white/10 shadow-lg ring-1 ring-white/5" style="animation:modal-in 0.28s cubic-bezier(0.16, 1, 0.3, 1)">
        
        <!-- Top shine effect -->
        <div class="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent"></div>

        <div class="p-8 text-center relative z-10">
          <!-- Icon Container -->
          <div class="relative w-16 h-16 rounded-2xl bg-slate-950 border border-white/5 shadow-inner flex items-center justify-center mx-auto mb-6 group transition-transform duration-300 hover:scale-105 hover:border-emerald-500/30">
            <i class="fas fa-lock text-2xl text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]"></i>
          </div>

          <!-- Titles -->
          <h2 class="text-2xl font-black mb-2 bg-gradient-to-br from-white via-white to-slate-400 bg-clip-text text-transparent tracking-tight">Admin Access</h2>
          <p class="text-slate-400 text-sm mb-8 font-medium">请输入管理员密码解锁控制台 🔐</p>

          <!-- Input Group -->
          <div class="relative group mb-6">
            <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <i class="fas fa-key text-slate-500 group-focus-within:text-emerald-400 transition-colors duration-300 text-sm"></i>
            </div>
            <input type="password" v-model="inputPassword" @keyup.enter="doLogin"
              class="block w-full pl-12 pr-4 py-3.5 bg-slate-950/50 border border-white/5 rounded-xl text-white placeholder-slate-600 text-sm font-medium outline-none focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20 focus:bg-slate-900/80 transition-all duration-300 shadow-inner"
              placeholder="Enter your password" autocomplete="current-password">
            <p v-if="loginError" class="mt-2 text-xs text-red-400 text-left">{{ loginError }}</p>
          </div>

          <!-- Submit Button -->
          <button @click="doLogin" :disabled="loggingIn"
            class="relative overflow-hidden w-full py-3.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-sm font-bold rounded-xl transition-all duration-300 shadow-[0_0_20px_rgba(16,185,129,0.3)] hover:shadow-[0_0_30px_rgba(52,211,153,0.5)] hover:-translate-y-0.5 active:translate-y-0 cursor-pointer flex items-center justify-center gap-2 group/btn disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:translate-y-0">
            {{ loggingIn ? '验证中...' : '进入系统' }}
            <i class="fas fa-arrow-right text-sm opacity-80 group-hover/btn:translate-x-1 transition-transform duration-300"></i>
            <!-- Shinning effect on button hover -->
            <div class="absolute inset-0 -translate-x-[150%] skew-x-[-20deg] bg-gradient-to-r from-transparent via-white/20 to-transparent group-hover/btn:animate-[shine_1s_ease-in-out]"></div>
          </button>
        </div>

        <!-- Footer -->
        <div class="bg-slate-950/30 border-t border-white/5 px-8 py-4 flex justify-between items-center text-xs text-slate-500 font-medium relative z-10">
          <span class="flex items-center gap-1.5">
            <i class="fas fa-shield-alt text-emerald-500/70 text-sm"></i>
            Secure Area
          </span>
          <router-link to="/" class="hover:text-emerald-400 transition-colors duration-300 flex items-center gap-1 group">
            返回首页
            <i class="fas fa-chevron-right text-[10px] group-hover:translate-x-0.5 transition-transform"></i>
          </router-link>
        </div>
      </div>
    </div>
  </transition>
</template>

<script setup>
import { useAuth } from '../../composables/useAuth';
const emit = defineEmits(['login']);
const { inputPassword, loginError, loggingIn, login } = useAuth();
const doLogin = () => login(() => emit('login'));
</script>

<style scoped>
@keyframes modal-in {
  from {
    opacity: 0;
    transform: scale(0.95) translateY(10px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}
@keyframes shine {
  0% { transform: translateX(-150%) skewX(-20deg); }
  100% { transform: translateX(150%) skewX(-20deg); }
}
</style>
