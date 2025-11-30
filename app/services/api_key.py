"""API Key 管理模块 - 支持多 API Key 管理"""

import secrets
import string
from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel

from app.core.logger import logger


class APIKeyInfo(BaseModel):
    """API Key 信息模型"""
    key: str                                    # sk-XXX 格式，48位
    note: str = ""                              # 备注
    expire_time: Optional[int] = None           # 过期时间戳（毫秒），None 表示永不过期
    ip_whitelist: List[str] = []                # IP 白名单列表
    created_time: int                           # 创建时间戳（毫秒）
    last_used_time: Optional[int] = None        # 最后使用时间戳（毫秒）
    status: str = "active"                      # active, disabled, expired

    class Config:
        json_schema_extra = {
            "example": {
                "key": "sk-" + "x" * 45,
                "note": "测试 API Key",
                "expire_time": None,
                "ip_whitelist": ["192.168.1.100", "10.0.0.0/24"],
                "created_time": 1234567890000,
                "last_used_time": 1234567890000,
                "status": "active"
            }
        }


class APIKeyManager:
    """API Key 管理器 - 单例模式"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.api_keys: Dict[str, APIKeyInfo] = {}  # key -> APIKeyInfo
            self.storage = None
            self._dirty = False  # 标记数据是否需要保存
            self._initialized = True

    def set_storage(self, storage):
        """设置存储引擎"""
        self.storage = storage
        logger.info(f"[APIKey] 存储引擎已设置: {type(storage).__name__}")

    async def _load_data(self):
        """从存储加载 API Key 数据"""
        try:
            if self.storage:
                data = await self.storage.load_api_keys()
            else:
                # 兼容性：从旧配置文件迁移
                data = {}

            # 解析数据
            self.api_keys = {}
            for key, value in data.items():
                try:
                    self.api_keys[key] = APIKeyInfo(**value)
                except Exception as e:
                    logger.error(f"[APIKey] 解析 API Key 失败: {key}, 错误: {e}")

            logger.info(f"[APIKey] 已加载 {len(self.api_keys)} 个 API Key")
        except Exception as e:
            logger.error(f"[APIKey] 加载数据失败: {e}")
            self.api_keys = {}

    async def _save_data(self):
        """保存 API Key 数据到存储"""
        try:
            # 转换为字典
            data = {
                key: info.model_dump()
                for key, info in self.api_keys.items()
            }

            if self.storage:
                await self.storage.save_api_keys(data)
                logger.info(f"[APIKey] 已保存 {len(data)} 个 API Key")
                self._dirty = False  # 清除 dirty 标志
            else:
                logger.warning("[APIKey] 未设置存储引擎，数据未保存")
        except Exception as e:
            logger.error(f"[APIKey] 保存数据失败: {e}")

    def _schedule_save(self):
        """标记数据需要保存（用于同步方法中）"""
        self._dirty = True

    async def save_if_dirty(self):
        """如果数据被标记为需要保存，则保存"""
        if self._dirty:
            await self._save_data()


    @staticmethod
    def generate_key() -> str:
        """生成 API Key（sk-XXX 格式，总长度 48 位）"""
        # sk- 前缀（3个字符）+ 45个随机字符 = 48个字符
        alphabet = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(alphabet) for _ in range(45))
        return f"sk-{random_part}"

    async def create_api_key(
        self,
        note: str = "",
        expire_time: Optional[int] = None,
        ip_whitelist: Optional[List[str]] = None
    ) -> APIKeyInfo:
        """创建新的 API Key

        Args:
            note: 备注
            expire_time: 过期时间戳（毫秒），None 表示永不过期
            ip_whitelist: IP 白名单列表

        Returns:
            APIKeyInfo: 创建的 API Key 信息
        """
        # 生成唯一的 key
        while True:
            key = self.generate_key()
            if key not in self.api_keys:
                break

        # 创建 API Key 信息
        api_key_info = APIKeyInfo(
            key=key,
            note=note,
            expire_time=expire_time,
            ip_whitelist=ip_whitelist or [],
            created_time=int(datetime.now().timestamp() * 1000),
            status="active"
        )

        # 保存
        self.api_keys[key] = api_key_info
        await self._save_data()

        logger.info(f"[APIKey] 创建 API Key: {key[:20]}..., 备注: {note}")
        return api_key_info

    async def delete_api_key(self, key: str) -> bool:
        """删除 API Key

        Args:
            key: API Key

        Returns:
            bool: 是否删除成功
        """
        if key not in self.api_keys:
            logger.warning(f"[APIKey] API Key 不存在: {key[:20]}...")
            return False

        del self.api_keys[key]
        await self._save_data()

        logger.info(f"[APIKey] 删除 API Key: {key[:20]}...")
        return True

    async def update_api_key(
        self,
        key: str,
        note: Optional[str] = None,
        expire_time: Optional[int] = None,
        ip_whitelist: Optional[List[str]] = None,
        status: Optional[str] = None
    ) -> bool:
        """更新 API Key 信息

        Args:
            key: API Key
            note: 备注
            expire_time: 过期时间戳（毫秒）
            ip_whitelist: IP 白名单列表
            status: 状态

        Returns:
            bool: 是否更新成功
        """
        if key not in self.api_keys:
            logger.warning(f"[APIKey] API Key 不存在: {key[:20]}...")
            return False

        api_key_info = self.api_keys[key]

        if note is not None:
            api_key_info.note = note
        if expire_time is not None:
            api_key_info.expire_time = expire_time
        if ip_whitelist is not None:
            api_key_info.ip_whitelist = ip_whitelist
        if status is not None:
            api_key_info.status = status

        await self._save_data()

        logger.info(f"[APIKey] 更新 API Key: {key[:20]}...")
        return True

    def verify_api_key(self, key: str, client_ip: Optional[str] = None) -> tuple[bool, str]:
        """验证 API Key

        Args:
            key: API Key
            client_ip: 客户端 IP 地址

        Returns:
            tuple[bool, str]: (是否验证成功, 错误消息)
        """
        try:
            # 检查 key 是否存在
            if key not in self.api_keys:
                return False, "API Key 不存在"

            api_key_info = self.api_keys[key]

            # 检查状态
            if api_key_info.status == "disabled":
                return False, "API Key 已被禁用"

            if api_key_info.status == "expired":
                return False, "API Key 已过期"

            # 检查过期时间
            if api_key_info.expire_time is not None:
                current_time = int(datetime.now().timestamp() * 1000)
                if current_time > api_key_info.expire_time:
                    # 自动标记为过期
                    api_key_info.status = "expired"
                    # 标记数据需要保存
                    self._schedule_save()
                    return False, "API Key 已过期"

            # 检查 IP 白名单
            if api_key_info.ip_whitelist and client_ip:
                if not self._check_ip_whitelist(client_ip, api_key_info.ip_whitelist):
                    logger.warning(f"[APIKey] IP 不在白名单: {client_ip}, Key: {key[:20]}...")
                    return False, f"客户端 IP {client_ip} 不在白名单中"

            # 更新最后使用时间
            api_key_info.last_used_time = int(datetime.now().timestamp() * 1000)
            # 标记数据需要保存
            self._schedule_save()

            return True, ""
        except Exception as e:
            logger.error(f"[APIKey] 验证 API Key 时发生异常: {e}", exc_info=True)
            return False, "服务器内部错误"

    @staticmethod
    def _check_ip_whitelist(client_ip: str, whitelist: List[str]) -> bool:
        """检查 IP 是否在白名单中

        支持：
        - 单个 IP: 192.168.1.100
        - IP 段（CIDR）: 10.0.0.0/24

        Args:
            client_ip: 客户端 IP
            whitelist: IP 白名单列表

        Returns:
            bool: 是否在白名单中
        """
        import ipaddress

        try:
            client_ip_obj = ipaddress.ip_address(client_ip)

            for ip_pattern in whitelist:
                try:
                    # 尝试作为 CIDR 解析
                    if '/' in ip_pattern:
                        network = ipaddress.ip_network(ip_pattern, strict=False)
                        if client_ip_obj in network:
                            return True
                    else:
                        # 单个 IP
                        if client_ip_obj == ipaddress.ip_address(ip_pattern):
                            return True
                except ValueError:
                    logger.warning(f"[APIKey] 无效的 IP 白名单格式: {ip_pattern}")
                    continue

            return False
        except ValueError:
            logger.error(f"[APIKey] 无效的客户端 IP: {client_ip}")
            return False

    def get_all_api_keys(self) -> List[APIKeyInfo]:
        """获取所有 API Key 列表"""
        return list(self.api_keys.values())

    def get_api_key(self, key: str) -> Optional[APIKeyInfo]:
        """获取指定的 API Key 信息"""
        return self.api_keys.get(key)

    def get_statistics(self) -> Dict[str, Any]:
        """获取 API Key 统计信息"""
        total = len(self.api_keys)
        active = sum(1 for key in self.api_keys.values() if key.status == "active")
        disabled = sum(1 for key in self.api_keys.values() if key.status == "disabled")
        expired = sum(1 for key in self.api_keys.values() if key.status == "expired")

        return {
            "total": total,
            "active": active,
            "disabled": disabled,
            "expired": expired
        }


# 全局实例
api_key_manager = APIKeyManager()
