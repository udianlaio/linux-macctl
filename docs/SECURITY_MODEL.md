# Public security model

Linux-macctl 的公开发行版把 Linux gateway、OpenSSH trust、macOS Helper/TCC 分成独立层。安装器只建立本机软件与 SSH 信任；它不授予高影响动作权限，也不绕过 macOS TCC。未知 target/action 必须 fail closed。运行时配置与凭据不属于源代码供应链。
