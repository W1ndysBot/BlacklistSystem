# script/BlacklistSystem/main.py
# 黑名单系统

import logging
import os
import re
import sys
import json
import requests

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
        return True
    return False


# 检查是否在黑名单
def is_blacklisted(group_id, user_id):
    blacklist = read_blacklist(group_id)
    return user_id in blacklist


# 黑名单管理
async def manage_blacklist(websocket, message_id, group_id, raw_message, is_authorized):

    # 鉴权
    if not is_authorized:
        return
    if raw_message.startswith("bladd"):

        # 匹配CQ码或QQ号
        matches = re.findall(r"(\d+)", raw_message)
        added_users = []
        for target_user_id in matches:

            add_to_blacklist(group_id, target_user_id)
            await set_group_kick(websocket, group_id, target_user_id)
            added_users.append(target_user_id)

        if added_users:
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}]用户{','.join(added_users)}已添加到黑名单，已踢出并不再接受入群。",
            )
            logging.info(
                f"添加群{group_id}黑名单用户{','.join(added_users)}到黑名单并踢出"
            )

    elif raw_message.startswith("blrm"):

        # 匹配CQ码或QQ号
        matches = re.findall(r"(\d+)", raw_message)
        removed_users = []

        for target_user_id in matches:
            if remove_from_blacklist(group_id, target_user_id):
                removed_users.append(target_user_id)

        if removed_users:
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}]用户[{'，'.join(removed_users)}]已从黑名单中移除。",
            )
            logging.info(f"从群{group_id}黑名单删除用户[{'，'.join(removed_users)}]")

    elif raw_message.startswith("blcheck"):

        # 匹配CQ码或QQ号
        matches = re.findall(r"(\d+)", raw_message)
        for target_user_id in matches:
            logging.info(f"检查群{group_id}用户{target_user_id}是否在黑名单中")
            if is_blacklisted(group_id, target_user_id):
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]用户{target_user_id}在黑名单中。",
                )
            else:
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}]用户{target_user_id}不在黑名单中。",
                )

    elif raw_message.startswith("bllist"):
        logging.info(f"执行查看黑名单命令")
        blacklist = read_blacklist(group_id)
        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}]群{group_id}黑名单:\n" + "\n".join(blacklist),
        )


# 处理黑名单消息事件
async def handle_blacklist_group_message(websocket, msg):
    try:
        # 确保数据目录存在
        os.makedirs(DATA_DIR, exist_ok=True)

        user_id = str(msg.get("user_id"))
        group_id = str(msg.get("group_id"))
        raw_message = msg.get("raw_message")
        role = msg.get("sender", {}).get("role")
        message_id = msg.get("message_id")

        if is_blacklisted(group_id, user_id):

            await send_group_msg(
                websocket,
                group_id,
                f"发现黑名单用户[{user_id}]发送消息，将踢出群聊。",
            )
            await set_group_kick(websocket, group_id, user_id)  # 踢出群聊
            await delete_msg(websocket, message_id)  # 撤回消息
            logging.info(f"发现黑名单用户[{user_id}]发送消息，将踢出群聊。")

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
        logging.error(f"处理黑名单消息事件失败:{e}")
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
            await set_group_kick(websocket, group_id, user_id)
            await set_group_add_request(
                websocket, flag, "group", False, "你已被加入黑名单。"
            )
            await send_group_msg(
                websocket,
                group_id,
                f"发现黑名单用户[{user_id}]申请入群，将拒绝申请。",
            )
            logging.info(f"发现黑名单用户[{user_id}]申请入群，将拒绝申请。")

    except Exception as e:
        logging.error(f"处理黑名单请求事件失败:{e}")
        return


# 处理进群通知，检测进群用户是否在黑名单
async def handle_blacklist_group_notice(websocket, msg):
    user_id = str(msg.get("user_id"))
    group_id = str(msg.get("group_id"))
    notice_type = str(msg.get("notice_type"))
    sub_type = str(msg.get("sub_type"))

    if notice_type != "group_increase":
        return

    # 如果用户在黑名单中，并且不是撤回消息，因为测试发现，撤回消息的user_id是被拉黑的用户
    if is_blacklisted(group_id, user_id):
        logging.info(f"发现黑名单用户[{user_id}]入群，将踢出。")
        await send_group_msg(
            websocket,
            group_id,
            f"发现黑名单用户[{user_id}]入群，将踢出。",
        )
        await set_group_kick(websocket, group_id, user_id)


# 统一事件处理入口
async def handle_events(websocket, msg):
    """统一事件处理入口"""
    post_type = msg.get("post_type", "response")  # 添加默认值
    try:
        # 处理回调事件
        if msg.get("status") == "ok":
            return

        post_type = msg.get("post_type")

        # 处理元事件
        if post_type == "meta_event":
            return

        # 处理消息事件
        elif post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                group_id = str(msg.get("group_id", ""))
                message_id = str(msg.get("message_id", ""))
                raw_message = str(msg.get("raw_message", ""))
                user_id = str(msg.get("user_id", ""))
                role = str(msg.get("sender", {}).get("role", ""))

                # 处理黑名单相关命令
                if raw_message.startswith("bl"):
                    await handle_blacklist_group_message(websocket, msg)
            elif message_type == "private":
                return

        # 处理通知事件
        elif post_type == "notice":
            if msg.get("notice_type") == "group":
                await handle_blacklist_group_notice(websocket, msg)

        # 处理请求事件
        elif post_type == "request":
            if msg.get("request_type") == "group":
                await handle_blacklist_request_event(websocket, msg)

    except Exception as e:
        error_type = {
            "message": "消息",
            "notice": "通知",
            "request": "请求",
            "meta_event": "元事件",
        }.get(post_type, "未知")

        logging.error(f"处理BlacklistSystem{error_type}事件失败: {e}")

        # 发送错误提示
        if post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                await send_group_msg(
                    websocket,
                    msg.get("group_id"),
                    f"处理BlacklistSystem{error_type}事件失败，错误信息：{str(e)}",
                )
            elif message_type == "private":
                await send_private_msg(
                    websocket,
                    msg.get("user_id"),
                    f"处理BlacklistSystem{error_type}事件失败，错误信息：{str(e)}",
                )
