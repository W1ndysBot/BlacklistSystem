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


# 读取云端黑名单
def read_cloud_blacklist():
    url = "https://ghp.ci/https://raw.githubusercontent.com/W1ndys/AD_Blacklist/refs/heads/main/qq.json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return []


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
                    f"[CQ:reply,id={message_id}][+]用户{target_user_id}在黑名单中。",
                )
            else:
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:reply,id={message_id}][+]用户{target_user_id}不在黑名单中。",
                )

    # 扫描群内是否有人在黑名单
    elif raw_message.startswith("blscan"):
        logging.info(f"执行云端黑名单扫描命令")
        FLAG = False
        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}][+]即将读取云端黑名单，请稍等...",
        )

        cloud_blacklist = read_cloud_blacklist()

        user_list = await get_group_member_list_qq(websocket, group_id)

        blacklist_user_ids = []
        for blacklist_user_id in user_list:
            blacklist_user_id = str(blacklist_user_id)  # 转换为字符串
            if blacklist_user_id in cloud_blacklist:
                logging.info(
                    f"发现群{group_id}的用户{blacklist_user_id}在云端黑名单中，将记录。"
                )
                blacklist_user_ids.append(blacklist_user_id)
                FLAG = True

        if not FLAG:
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}][+]群{group_id}没有人在云端黑名单中。",
            )
        else:
            blacklist_user_ids_str = "\n".join(blacklist_user_ids)
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}][+]检测出本群云端黑名单列表如下：\n"
                + blacklist_user_ids_str
                + "\n发送 t+QQ号，将踢出该用户，发送 bltall 将踢出所有云端黑名单用户。",
            )

    elif raw_message.startswith("bltall"):
        logging.info(f"[+]踢出{group_id}所有云端黑名单用户")

        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}][+]即将踢出所有云端黑名单用户，请稍等...",
        )

        # 获取群成员列表
        user_list = await get_group_member_list_qq(websocket, group_id)

        # 遍历云端黑名单
        cloud_blacklist = read_cloud_blacklist()
        kicked_users = []
        for blacklist_user_id in cloud_blacklist:
            if blacklist_user_id in user_list:
                await set_group_kick(websocket, group_id, blacklist_user_id)
                kicked_users.append(blacklist_user_id)

        if kicked_users:
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}][+]已踢出以下云黑名单用户：{', '.join(kicked_users)}。",
            )
        else:
            await send_group_msg(
                websocket,
                group_id,
                f"[CQ:reply,id={message_id}][+]没有云端黑名单用户被踢出。",
            )

    elif raw_message.startswith("bllist"):
        logging.info(f"执行查看黑名单命令")
        blacklist = read_blacklist(group_id)
        await send_group_msg(
            websocket,
            group_id,
            f"[CQ:reply,id={message_id}][+]群{group_id}黑名单:\n"
            + "\n".join(blacklist),
        )


# 黑名单系统菜单
async def Blacklist(websocket, group_id, message_id):
    message = (
        f"[CQ:reply,id={message_id}]\n"
        + """黑名单系统

bladd@或QQ号 添加黑名单
blrm@或QQ号 删除黑名单
bllist 查看黑名单
blcheck@或QQ号 检查黑名单
blscan 读取云端扫描群内是否有人在黑名单
bltall 踢出所有云端黑名单用户

黑名单系统默认开启，无开关"""
    )
    await send_group_msg(websocket, group_id, message)


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
        sub_type = msg.get("sub_type")
        if raw_message == "blacklist" or raw_message == "黑名单系统":
            await Blacklist(websocket, group_id, message_id)

        if is_blacklisted(group_id, user_id):

            # 貌似不用判断sub_type，因为这是在发消息时候的判断
            # if sub_type != "invite" and sub_type != "approve":
            await send_group_msg(
                websocket,
                group_id,
                f"[+]发现黑名单用户[{user_id}]发送消息，将踢出群聊。",
            )
            await set_group_kick(websocket, group_id, user_id)
            await delete_msg(websocket, message_id)
            logging.info(f"[+]发现黑名单用户[{user_id}]发送消息，将踢出群聊。")

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
                f"[+]发现黑名单用户[{user_id}]申请入群，将拒绝申请。",
            )
            logging.info(f"[+]发现黑名单用户[{user_id}]申请入群，将拒绝申请。")

    except Exception as e:
        logging.error(f"处理黑名单请求事件失败:{e}")
        return


# 处理进群通知，检测进群用户是否在黑名单
async def handle_blacklist_group_notice(websocket, msg):
    user_id = str(msg.get("user_id"))
    group_id = str(msg.get("group_id"))
    notice_type = str(msg.get("notice_type"))
    sub_type = str(msg.get("sub_type"))

    # 如果用户在黑名单中，并且不是撤回消息，因为测试发现，撤回消息的user_id是被拉黑的用户
    if (
        is_blacklisted(group_id, user_id)
        and notice_type != "group_recall"
        and sub_type != "invite"
        and sub_type != "approve"
    ):
        logging.info(f"[+]发现黑名单用户[{user_id}]申请入群，将拒绝入群。")
        await send_group_msg(
            websocket,
            group_id,
            f"[+]发现黑名单用户[{user_id}]申请入群，将拒绝入群。",
        )
        await set_group_kick(websocket, group_id, user_id)
