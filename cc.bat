@echo off
rem frpwaf - Claude Code 启动器
rem 1) 锚定工作目录到仓库根，避免 cwd 漂移导致的相对路径错乱；
rem 2) 不附带 --dangerously-skip-permissions：本仓库有 hooks 拦截体系与工程红线，
rem    保留权限确认；确需免确认请自行在命令行加参数（风险自负）。
cd /d "%~dp0"
claude %*
