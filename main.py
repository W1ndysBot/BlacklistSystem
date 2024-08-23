# script/BlacklistSystem/main.py
# 黑名单系统

import logging
import os
import re
import sys
import json

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
from app.switch import load_switch, save_switch


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


# 黑名单管理
async def manage_blacklist(websocket, message_id, group_id, raw_message, is_authorized):
    if not is_authorized:
        return

    if raw_message.startswith("bl-add "):
        target_user_id = raw_message.split()[1]
        logging.info(f"添加黑名单用户 {target_user_id}")
        # 修改正则表达式以匹配新的CQ码格式
        match = re.search(r"\[CQ:at,qq=(\d+),name=.*\]", target_user_id)
        if match:
            target_user_id = match.group(1)  # 提取QQ号
        logging.info(f"添加黑名单用户 {target_user_id} 到黑名单并踢出")
        add_to_blacklist(group_id, target_user_id)
        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}]用户 {target_user_id} 已添加到黑名单，将踢出并不再接受入群。",
        )
        await set_group_kick(websocket, group_id, target_user_id)
    elif raw_message.startswith("bl-rm "):
        logging.info(f"执行删除黑名单命令")
        target_user_id = raw_message.split()[1]
        # 修改正则表达式以匹配新的CQ码格式
        match = re.search(r"\[CQ:at,qq=(\d+),name=.*\]", target_user_id)
        if match:
            target_user_id = match.group(1)  # 提取QQ号
        logging.info(f"从黑名单删除用户 {target_user_id}")
        remove_from_blacklist(group_id, target_user_id)
        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}]用户 {target_user_id} 已从黑名单中移除。",
        )
    elif raw_message.startswith("bl-check "):
        target_user_id = raw_message.split()[1]
        # 修改正则表达式以匹配新的CQ码格式
        match = re.search(r"\[CQ:at,qq=(\d+),name=.*\]", target_user_id)
        if match:
            target_user_id = match.group(1)  # 提取QQ号
        logging.info(f"检查用户 {target_user_id} 是否在黑名单中")
        if is_blacklisted(group_id, target_user_id):
            await send_group_msg(
                websocket,
                group_id,
                f"用户 {target_user_id} 在黑名单中。",
            )
        else:
            await send_group_msg(
                websocket,
                group_id,
                f"用户 {target_user_id} 不在黑名单中。",
            )
    elif raw_message.startswith("bl-list"):
        logging.info(f"执行查看黑名单命令")
        blacklist = read_blacklist(group_id)
        await send_group_msg(websocket, group_id, f"黑名单用户: {', '.join(blacklist)}")


# 处理黑名单消息事件
async def handle_blacklist_message_group(websocket, msg):
    try:
        # 确保数据目录存在
        os.makedirs(DATA_DIR, exist_ok=True)

        user_id = str(msg.get("user_id"))
        group_id = str(msg.get("group_id"))
        raw_message = msg.get("raw_message")
        role = msg.get("sender", {}).get("role")
        message_id = msg.get("message_id")

        if is_blacklisted(group_id, user_id):
            logging.info(f"发现黑名单用户 {user_id}，将踢出群聊，并不再接受入群。")
            await send_group_msg(
                websocket,
                group_id,
                f"发现黑名单用户 {user_id}，将踢出群聊，并不再接受入群。",
            )
            await set_group_kick(websocket, group_id, user_id)

        else:
            # 处理管理员命令
            is_admin = is_group_admin(role)  # 是否是群管理员
            is_owner = is_group_owner(role)  # 是否是群主
            is_authorized = (is_admin or is_owner) or (
                user_id in owner_id
            )  # 是否是群主或管理员或root管理员

            await manage_blacklist(
                websocket, message_id, group_id, raw_message, is_authorized
            )

    except Exception as e:
        logging.error(f"处理黑名单消息事件失败: {e}")
        return


# 处理黑名单请求事件
async def handle_blacklist_request_event(websocket, msg):
    try:
        # 确保数据目录存在
        os.makedirs(DATA_DIR, exist_ok=True)

        group_id = str(msg.get("group_id"))
        user_id = str(msg.get("user_id"))
        flag = str(msg.get("flag"))
        if is_blacklisted(group_id, user_id):
            logging.info(f"发现黑名单用户 {user_id}申请入群，将拒绝申请。")
            await set_group_add_request(
                websocket, flag, "group", False, "你已被加入黑名单。"
            )

            await send_group_msg(
                websocket,
                group_id,
                f"发现黑名单用户 {user_id}申请入群，将拒绝申请。",
            )

    except Exception as e:
        logging.error(f"处理黑名单请求事件失败: {e}")
        return


# 处理进群通知，检测进群用户是否在黑名单
async def handle_blacklist_group_notice(websocket, msg):
    user_id = str(msg.get("user_id"))
    group_id = str(msg.get("group_id"))
    notice_type = msg.get("notice_type")

    # 如果用户在黑名单中，并且不是撤回消息，因为测试发现，撤回消息的user_id是被拉黑的用户
    if is_blacklisted(group_id, user_id) and notice_type != "group_recall":
        logging.info(f"发现黑名单用户 {user_id}，将踢出群聊，并不再接受入群。")
        await send_group_msg(
            websocket,
            group_id,
            f"发现黑名单用户 {user_id}，将踢出群聊，并不再接受入群。",
        )
        await set_group_kick(websocket, group_id, user_id)
    pass


# 处理黑名单定时任务
async def handle_blacklist_cron_task(websocket):
    pass
