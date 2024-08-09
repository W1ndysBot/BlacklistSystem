# script/blacklist/main.py
# 黑名单系统

import logging
import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


async def handle_group_message(websocket, msg):
    try:
        user_id = msg.get("user_id")
        group_id = msg.get("group_id")
        raw_message = msg.get("raw_message")
        role = msg.get("sender", {}).get("role")
        message_id = msg.get("message_id")

    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return


async def handle_private_message(websocket, msg):
    try:
        user_id = msg.get("user_id")
        raw_message = msg.get("raw_message")

    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return
