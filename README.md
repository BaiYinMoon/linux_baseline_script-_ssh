# linux_baseline_script-_ssh
# 简介

脚本检测时间
平均在3秒到20秒不等一台主机

# 主要检查项

检查是否设置除root之外UID为0的用户
检查是否设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户
检查设备密码复杂度策略
检查 /etc/login.defs 中的口令策略
检查是否存在空口令账户
检查密码重复使用次数限制
检查账户认证失败次数限制
检查umask命令输出
检查 /root/.bashrc 中的 umask
检查 /etc/bashrc 中的 umask
检查 /etc/profile 中的 umask
检查 /etc/login.defs 中的 umask
检查是否设置SSH登录前警告Banner
检查安全事件日志配置
检查日志文件权限设置
检查是否配置远程日志功能
检查是否启用审计服务
检查重要目录或文件权限设置
检查FTP用户上传的文件所具有的权限
检查是否禁用Telnet协议
检查是否使用PAM认证模块禁止wheel组之外的用户su为root
检查是否修改SNMP默认团体字
检查是否禁止root用户远程登录
检查系统openssh安全配置
检查是否禁止匿名用户登录
检查是否删除了潜在危险文件
检查是否设置命令行界面超时退出
检查root用户的path环境变量
检查历史命令设置
检查系统是否禁用Ctrl+Alt+Delete组合键
检查是否使用NTP保持时间同步
检查是否限制访问IP

# 注意事项（必看）

为了系统稳定性最高支持50个同时检测；
平均一台主机检测时间为1.2秒以内；
文件格式为：

```bash
ip,username,passwd,port
```

注意使用英文逗号分割；
port 不指定默认为22；
检测后的结果自动保存在当前目录的linux-baseline-resoult文件夹下ip.xlsx；
出现问题的自动保存在当前目录的fail.txt文本中；如果没有txt文件生成则没有问题

# 运行脚本

```bash
chmod +x linux-script-ssh
./linux-script-ssh -file=hosts.txt
```

