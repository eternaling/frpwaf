@echo off
rem frpwaf - Codex 启动器
rem 1) 锚定工作目录到仓库根，保证 .codex/hooks.json 相对路径生效；
rem 2) 不附带 --dangerously-bypass-approvals-and-sandbox：本仓库有 hooks 拦截体系，
rem    保留审批与沙箱；确需绕过请自行在命令行加参数（风险自负）。
cd /d "%~dp0"
codex %*
