# BlacklistSystem

黑名单系统

## 命令

bl-add 添加黑名单

bl-rm 删除黑名单

bl-list 查看黑名单

bl-check 检查黑名单

黑名单系统默认开启，无开关

## 更新日志

### 2024-09-26

- feat: 增加 blscan 命令，扫描群内是否有人在黑名单
- feat: 优化黑名单扫描，改为默认不踢群，仅记录
- feat: 增加 bltall 命令，踢出所有黑名单用户
- feat: 新增检查到有人在黑名单时，执行踢出并撤回所有消息

### 2024-08-25

- fix: 修复由于上层供应链的 JSON 导致设置群名片时无法正确解析正则的问题，重构代码逻辑，规范代码格式

### 2024-08-23

- fix: 去掉指令中的空格
- fix: 增加对黑名单检查的细节，如果用户在黑名单中，并且不是撤回消息，因为测试发现，撤回消息的 user_id 是被拉黑的用户，所以需要排除撤回消息

### 2024-08-18

- feat: 新增对进群用户的黑名单检查，如果用户在黑名单中，将踢出群聊，并不再接受入群

### 2024-08-12

- feat: 重构代码，精简命令
