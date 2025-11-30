"""认证模块 - API令牌验证"""

from typing import Optional
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import setting
from app.core.logger import logger


# Bearer安全方案
security = HTTPBearer(auto_error=False)


def _build_error(message: str, code: str = "invalid_token") -> dict:
    """构建认证错误"""
    return {
        "error": {
            "message": message,
            "type": "authentication_error",
            "code": code
        }
    }


def _get_client_ip(request: Request) -> str:
    """获取客户端 IP 地址"""
    # 优先从 X-Forwarded-For 获取（适用于反向代理场景）
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For 可能包含多个 IP，第一个是真实客户端 IP
        return forwarded_for.split(",")[0].strip()

    # 从 X-Real-IP 获取
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # 最后使用直接连接的 IP
    return request.client.host if request.client else "unknown"


class AuthManager:
    """认证管理器 - 验证API令牌"""

    @staticmethod
    def verify(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Optional[str]:
        """验证令牌"""
        # 延迟导入以避免循环依赖
        from app.services.api_key import api_key_manager

        # 获取客户端 IP
        client_ip = _get_client_ip(request)
        logger.debug(f"[Auth] 客户端 IP: {client_ip}")

        # 检查是否使用新的多 API Key 系统
        if api_key_manager.api_keys:
            # 使用新的多 API Key 验证
            if not credentials:
                logger.warning("[Auth] 使用多 API Key 系统，但未提供认证令牌")
                raise HTTPException(
                    status_code=401,
                    detail=_build_error("缺少认证令牌", "missing_token")
                )

            # 验证 API Key
            try:
                is_valid, error_msg = api_key_manager.verify_api_key(credentials.credentials, client_ip)
                if not is_valid:
                    logger.warning(f"[Auth] API Key 验证失败: {error_msg}")
                    raise HTTPException(
                        status_code=401,
                        detail=_build_error(error_msg, "invalid_token")
                    )

                logger.debug(f"[Auth] API Key 认证成功: {credentials.credentials[:20]}...")
                return credentials.credentials
            except HTTPException:
                # 重新抛出 HTTPException
                raise
            except Exception as e:
                # 捕获其他异常，记录日志并返回 500 错误
                logger.error(f"[Auth] API Key 验证过程中发生异常: {e}", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=_build_error("服务器内部错误", "internal_error")
                )

        # 回退到旧的单 API Key 验证（向后兼容）
        api_key = setting.grok_config.get("api_key")

        # 未设置时跳过
        if not api_key:
            logger.debug("[Auth] 未设置API_KEY，跳过验证")
            return credentials.credentials if credentials else None

        # 检查令牌
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail=_build_error("缺少认证令牌", "missing_token")
            )

        # 验证令牌
        if credentials.credentials != api_key:
            raise HTTPException(
                status_code=401,
                detail=_build_error(f"令牌无效，长度: {len(credentials.credentials)}", "invalid_token")
            )

        logger.debug("[Auth] 令牌认证成功")
        return credentials.credentials


# 全局实例
auth_manager = AuthManager()