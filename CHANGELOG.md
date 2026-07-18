# 更新日志

## 0.15.2

### 品牌与构建
- 统一品牌文案：前端登录页、用户门户、WebAuth、布局页的项目名与页脚统一为 RemLink（企业级安全远程接入网关）
- 移除阿里云镜像推送，Docker 镜像统一推送至 DockerHub（wsczx/remlink）
- README 项目描述更新

### 功能
- 新增：用户管理支持「下次登录强制修改密码」开关（仅本地用户生效），用户列表新增「需改密」标识
- 新增：门户首次登录强制改密内联体验——本地用户首次登录且需改密时，登录页内联弹出改密表单（无需旧密码），改密后若启用 OTP 则继续动态码二次认证，与 VPN 管道顺序（local → 强制改密 → OTP）保持一致
- 新增：WebAuth 首次登录强制改密内联体验（与门户一致），修复此前强制改密返回「未知响应」的问题
- 优化：原生 Cisco AnyConnect 弹窗改密页（/+CSCOE+/force-pwd）视觉风格对齐管理后台/门户/WebAuth（渐变背景 + 白色圆角卡片 + Element 蓝主色）

### 变更
- 调整：原生 SAML（企微/飞书单点登录）的 `sso-v2-browser-mode` 在移动端强制使用内置浏览器（与 WebAuth 行为一致），避免外部浏览器 localhost 回调在手机上不可用
- 移除：全局「首次登录强制改密」开关（系统设置→软件配置→服务配置）。强制改密现完全由用户级「强制改密」开关控制，不再有全局自动置标逻辑。触发仍只认用户级 ChangePwd
- 新增：批量导入用户支持「强制改密」列——导入模板（第 12 列 `change_pwd`）与 `UploadUser` 解析均已支持，逐用户控制是否首次登录强制改密，与用户管理弹窗开关对称（之前移除全局开关后导入用户无法强制改密，现已补回该能力）
- 调整：新增用户默认开启「强制改密」（用户管理弹窗 `change_pwd` 默认 `true`、导入模板示例 `change_pwd` 默认 `true`），恢复「新用户拿到初始密码必须改密」的安全默认；管理员仍可在新增/编辑时逐个取消勾选做例外

### 修复
- 修复：强制改密步骤对 `Type` 为空的本地用户判定错误——`forcepwd` 步骤原按 `ctx.UserInfo.Type != "local"` 跳过，而本地用户 `Type` 常为空字符串（与门户 `Type == "" || Type == "local"` 判定不一致），导致这类用户的强制改密被静默跳过。现改为使用管道内 `ctx.UserInfo`（`Type`/`ForcePwd` 已由 `ToAuthInfo` 投影，`local` 步已 `SetUserInfo` 装入），仅当 `ctx.UserInfo == nil`（如 resume）时按约定调 `LoadUserInfo` 兜底加载，避免重复查库；判定统一为 `Type != "" && Type != "local"` 判外部用户透明放行
- 修复：原生 Cisco AnyConnect 强制改密后无法进入后续认证步骤（如 local+otp）。根因：`handleSsoToken` 的 ForcePwd 分支在 `resumeAuthSession` 返回后无条件 `SessStore.Delete(sessionKey)`，把"续跑后仍为 StepPending（如还有 OTP）"的认证会话误删；用户提交 OTP 时会话已不存在，落到全新认证分支，而 AnyConnect 在 OTP 挑战阶段只回传动态码不回传主密码，local 步因密码为空直接失败。现移除该多余删除，会话最终清理由 `handlePipelineResult` 在 StepPass/StepFail 时统一完成
- 修复：`forcePwdMessage` 用 `fmt.Fprintf` 拼 HTML 时，CSS 渐变里的 `0%/40%/100%` 被当成格式动词导致输出乱码（密码错误/弱密码提示页、OpenConnect 成功页），已转义为 `%%`
- 修复：强制改密触发逻辑——原实现要求全局「首次登录必须改密」开关开启才生效，导致用户级单独勾选「下次登录强制修改密码」在全局关时无效；现改为仅按用户级 ChangePwd 触发
- 修复：管理后台关闭短信功能时清空已配置服务商密钥/签名/模板的问题，关闭仅停用、不再清除配置
- 优化：清理认证/改密链路中的重复查库，统一以管道内 `ctx.UserInfo` 为单一来源。`ForcePwdSubmit`（`/+CSCOE+/force-pwd/submit`）原先 `dbdata.One` 全量查用户仅为取 `Id` 再 `ID(u.Id).Update`，改为按 `username` 直接 `Update`；`SendOtpToUser`（OTP 发送）原签名 `(username, info)` 中 `username` 与 `info.Username` 重复，且门户调用传 `nil` 会再查一次库。现改为仅收 `info *auth.UserInfo`：管道路径传 `ctx.UserInfo`、门户传 `user.ToAuthInfo()`，调用方均持有完整用户对象，彻底去掉冗余的 `username` 参数与回退查库（新增 `auth.UserInfo.Email` 投影字段）。WebAuth 门户内联改密（`link_webauth.go`）同样存在"查全量用户仅取 `Id` 再 `ID(u.Id).Update`"的冗余，一并改为按 `username` 直接 `Update`
