// 全局的 axios 默认值
import axios from "axios";
import { logout as doLogout } from "./auth";

axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded';

if (process.env.NODE_ENV !== 'production') {
    axios.defaults.baseURL = process.env.VUE_APP_API_BASE || '';
}

function request(vm) {
    // HTTP 请求拦截器
    axios.interceptors.request.use(config => {
        return config;
    });

    // HTTP 响应拦截器
    // 统一处理 401 状态，token 过期的处理，清除token跳转login
    axios.interceptors.response.use(null, err => {
        // 网络错误/超时/CORS：err.response 可能为 undefined
        if (!err.response) {
            return Promise.reject(err);
        }
        // 没有登录或令牌过期
        if (err.response.status === 401) {
            if (vm.$router.currentRoute.path === '/portal') {
                return Promise.reject(err);
            }
            doLogout();
            vm.$router.push('/login');
        }
        return Promise.reject(err);
    });
}

export default request;
