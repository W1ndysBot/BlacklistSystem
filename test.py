blacklist_user_ids = ["1234567890", "1234567891", "1234567892"]
print(
    f"[CQ:reply,id=1234567890][+]检测出本群云端黑名单列表如下：{'\n'.join(blacklist_user_ids)}发送 t+QQ号，将踢出该用户，发送 bltall 将踢出所有云端黑名单用户。"
)
