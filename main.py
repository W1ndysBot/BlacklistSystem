# script/BlacklistSystem/main.py
# 黑名单系统

import logging
import os
import re
import sys
import json
import asyncio

# 数据存储路径
DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "BlacklistSystem",
)

# 添加项目根目录到sys.path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)


from app.config import owner_id
from app.api import *


# 是否是群主
def is_group_owner(role):
    return role == "owner"


# 是否是管理员
def is_group_admin(role):
    return role == "admin"


# 是否是管理员或群主或root管理员
def is_authorized(role, user_id):
    is_admin = is_group_admin(role)
    is_owner = is_group_owner(role)
    return (is_admin or is_owner) or (user_id in owner_id)


# 读取黑名单
def read_blacklist(group_id):
    file_path = os.path.join(DATA_DIR, f"{group_id}.json")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


# 保存黑名单
def save_blacklist(group_id, blacklist):
    file_path = os.path.join(DATA_DIR, f"{group_id}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(blacklist, f, ensure_ascii=False, indent=4)


# 添加黑名单
def add_to_blacklist(group_id, user_id):
    blacklist = read_blacklist(group_id)
    if user_id not in blacklist:
        blacklist.append(user_id)
        save_blacklist(group_id, blacklist)


# 移除黑名单
def remove_from_blacklist(group_id, user_id):
    blacklist = read_blacklist(group_id)
    if user_id in blacklist:
        blacklist.remove(user_id)
        save_blacklist(group_id, blacklist)


# 检查是否在黑名单
def is_blacklisted(group_id, user_id):
    blacklist = read_blacklist(group_id)
    return user_id in blacklist


async def handle_blacklist_message_group(websocket, msg):
    try:
        user_id = str(msg.get("user_id"))
        group_id = str(msg.get("group_id"))
        raw_message = msg.get("raw_message")
        role = msg.get("sender", {}).get("role")
        message_id = msg.get("message_id")

        if is_blacklisted(group_id, user_id):
            logging.info(f"发现黑名单用户 {user_id}，将踢出群聊。")
            asyncio.create_task(
                send_group_msg(
                    websocket, group_id, f"发现黑名单用户 {user_id}，将踢出群聊。"
                )
            )
            asyncio.create_task(set_group_kick(websocket, group_id, user_id))

        else:
            # 处理管理员命令
            if is_authorized(role, user_id):
                if raw_message.startswith("blacklist add "):
                    if "[CQ:at,qq=" in raw_message:
                        target_user_id = raw_message.split("[CQ:at,qq=")[1].split(",")[
                            0
                        ]
                    else:
                        target_user_id = raw_message.split(" ")[2]
                    add_to_blacklist(group_id, target_user_id)
                    asyncio.create_task(
                        send_group_msg(
                            websocket,
                            group_id,
                            f"用户 {target_user_id} 已被加入黑名单。",
                        )
                    )
                elif raw_message.startswith("blacklist rm "):
                    if "[CQ:at,qq=" in raw_message:
                        target_user_id = raw_message.split("[CQ:at,qq=")[1].split(",")[
                            0
                        ]
                    else:
                        target_user_id = raw_message.split(" ")[2]
                    remove_from_blacklist(group_id, target_user_id)
                    asyncio.create_task(
                        send_group_msg(
                            websocket,
                            group_id,
                            f"用户 {target_user_id} 已被移出黑名单。",
                        )
                    )
                elif raw_message.startswith("blacklist list"):
                    blacklist = read_blacklist(group_id)
                    asyncio.create_task(
                        send_group_msg(
                            websocket, group_id, f"黑名单用户: {', '.join(blacklist)}"
                        )
                    )
                elif raw_message.startswith("blacklist check "):
                    target_user_id = raw_message.split(" ")[2]
                    if is_blacklisted(group_id, target_user_id):
                        asyncio.create_task(
                            send_group_msg(
                                websocket,
                                group_id,
                                f"用户 {target_user_id} 在黑名单中。",
                            )
                        )
                    else:
                        asyncio.create_task(
                            send_group_msg(
                                websocket,
                                group_id,
                                f"用户 {target_user_id} 不在黑名单中。",
                            )
                        )
                else:
                    if raw_message == "blacklist":
                        menu = (
                            "黑名单菜单:\n"
                            "1. blacklist add [CQ:at,qq=用户ID] - 添加用户到黑名单\n"
                            "2. blacklist rm [CQ:at,qq=用户ID] - 从黑名单移除用户\n"
                            "3. blacklist list - 显示黑名单用户列表\n"
                            "4. blacklist check 用户ID - 检查用户是否在黑名单中"
                        )
                        asyncio.create_task(send_group_msg(websocket, group_id, menu))
                    else:
                        # 处理正常消息
                        pass

    except Exception as e:
        logging.error(f"处理黑名单消息事件失败: {e}")
        return


async def handle_blacklist_request_event(websocket, msg):
    try:
        group_id = str(msg.get("group_id"))
        user_id = str(msg.get("user_id"))
        flag = str(msg.get("flag"))
        if is_blacklisted(group_id, user_id):
            logging.info(f"发现黑名单用户 {user_id}申请入群，将拒绝申请。")
            asyncio.create_task(
                set_group_add_request(
                    websocket, flag, "group", False, "你已被加入黑名单。"
                )
            )
            asyncio.create_task(
                send_group_msg(
                    websocket,
                    group_id,
                    f"发现黑名单用户 {user_id}申请入群，将拒绝申请。",
                )
            )
    except Exception as e:
        logging.error(f"处理黑名单请求事件失败: {e}")
        return
