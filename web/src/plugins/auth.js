import Vue from 'vue'
import axios from 'axios'

// 使用 Vue 响应式对象管理登录态（仅存内存，不存 localStorage）
// token 通过 HttpOnly Cookie 由浏览器自动管理，JS 不可访问
const state = Vue.observable({
    user: null,
    checked: false,
    showFakeDNS: false,
})

export function getUser() {
    return state.user
}

export function setUser(username) {
    state.user = username
    state.checked = true
}

export function isChecked() {
    return state.checked
}
export function getShowFakeDNS() {
    return state.showFakeDNS
}

// checkAuth 调用后端验证 Cookie 中的 JWT 是否有效，并获取当前用户名
// 同时获取 showFakeDNS 配置，确保页面渲染前就绪
export async function checkAuth() {
    try {
        const resp = await axios.get('/base/auth_check')
        if (resp.data && resp.data.code === 0 && resp.data.data) {
            state.user = resp.data.data.admin_user
            state.checked = true
            // 认证通过后获取 showFakeDNS
            try {
                const homeResp = await axios.get('/set/home')
                if (homeResp.data && homeResp.data.data) {
                    state.showFakeDNS = !!homeResp.data.data.show_fakedns
                }
            } catch {
                // /set/home 失败不影响登录
            }
            return true
        }
    } catch {
        // token 无效或网络错误
    }
    state.checked = true
    state.user = null
    return false
}

// logout 调用后端清除 HttpOnly Cookie，并清空内存中的用户状态
export async function logout() {
    try {
        await axios.post('/base/logout')
    } catch {
        // 忽略错误，本地状态仍然清除
    }
    state.user = null
    state.checked = false
}
