"""视频生成API路由 - 专门的视频生成接口"""

import re
import time
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional

from app.core.auth import auth_manager
from app.core.exception import GrokApiException
from app.core.logger import logger
from app.services.grok.client import GrokClient
from app.models.openai_schema import VideoGenerationRequest, VideoGenerationResponse


router = APIRouter(prefix="/videos", tags=["视频生成"])


@router.post("/generations", response_model=VideoGenerationResponse)
async def generate_video(request: VideoGenerationRequest, _: Optional[str] = Depends(auth_manager.verify)):
    """生成视频

    通过提供一张图片和提示词来生成视频。

    Args:
        request: 视频生成请求，包含图片URL和提示词

    Returns:
        VideoGenerationResponse: 包含生成的视频URL

    Raises:
        HTTPException: 当生成失败时
    """
    try:
        logger.info(f"[Video] 收到视频生成请求 - 提示词: {request.prompt[:50]}...")

        # 构建OpenAI格式的请求（使用视频模型）
        openai_request = {
            "model": request.model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": request.image_url}
                        },
                        {
                            "type": "text",
                            "text": request.prompt
                        }
                    ]
                }
            ],
            "stream": False
        }

        # 调用Grok客户端生成视频
        result = await GrokClient.openai_to_grok(openai_request)

        # 调试：打印result的结构
        logger.info(f"[Video] 收到Grok响应，类型: {type(result)}")

        # 如果是Pydantic对象，转换为字典以便查看
        from pydantic import BaseModel
        result_dict = result.model_dump() if isinstance(result, BaseModel) else result

        if isinstance(result_dict, dict):
            logger.info(f"[Video] 响应keys: {list(result_dict.keys())}")
            # 只打印部分关键信息，避免日志过长
            if "choices" in result_dict and len(result_dict["choices"]) > 0:
                content = result_dict["choices"][0].get("message", {}).get("content", "")
                logger.info(f"[Video] content长度: {len(content)}, 前200字符: {content[:200]}")

        # 提取视频URL
        video_url = extract_video_url(result)

        if not video_url:
            logger.warning("[Video] 响应中未找到视频URL")
            raise HTTPException(
                status_code=500,
                detail={
                    "error": {
                        "message": "视频生成失败：未能获取视频URL",
                        "type": "video_generation_error",
                        "code": "no_video_url"
                    }
                }
            )

        # 构建响应
        response = VideoGenerationResponse(
            id=result.get("id", f"video-{int(time.time())}"),
            model=request.model,
            created=result.get("created", int(time.time())),
            video_url=video_url,
            status="completed",
            prompt=request.prompt
        )

        logger.info(f"[Video] 视频生成成功: {video_url}")
        return response

    except GrokApiException as e:
        logger.error(f"[Video] Grok API错误: {e} - 详情: {e.details}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "message": str(e),
                    "type": e.error_code or "grok_api_error",
                    "code": e.error_code or "unknown"
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Video] 视频生成失败: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "message": "服务器内部错误",
                    "type": "internal_error",
                    "code": "internal_server_error"
                }
            }
        )


def extract_video_url(result) -> Optional[str]:
    """从Grok响应中提取视频URL

    Args:
        result: Grok API的响应结果（可能是dict或Pydantic对象）

    Returns:
        视频URL，如果未找到则返回None
    """
    logger.info(f"[Video] extract_video_url 被调用，result类型: {type(result)}")

    try:
        # 如果是Pydantic对象，转换为字典
        from pydantic import BaseModel
        if isinstance(result, BaseModel):
            logger.info("[Video] 检测到Pydantic对象，转换为字典")
            result = result.model_dump()

        # 从choices中提取消息内容
        if "choices" in result and len(result["choices"]) > 0:
            choice = result["choices"][0]
            message = choice.get("message", {})
            content = message.get("content", "")

            logger.info(f"[Video] 提取视频URL - content长度: {len(content)}")
            logger.info(f"[Video] 提取视频URL - content前500字符: {content[:500]}")

            # 查找视频URL - 支持多种URL格式
            # 使用正则表达式提取URL，按优先级排序
            url_patterns = [
                # 1. <video src="..."> 标签中的URL（支持任意域名和视频扩展名）
                r'<video[^>]+src=["\']([^"\']+\.(?:mp4|webm|mov|avi|mkv))["\']',
                # 2. 直接的视频文件URL（支持任意域名）
                r'https?://[^\s<>"\']+\.(?:mp4|webm|mov|avi|mkv)',
                # 3. grok.com/imagine/xxx 格式
                r'https://grok\.com/imagine/[a-zA-Z0-9_-]+',
                # 4. assets.grok.com 格式
                r'https://assets\.grok\.com/post/[a-zA-Z0-9_/-]+',
                # 5. /images/ 路径的URL（自定义域名）
                r'https?://[a-zA-Z0-9.-]+/images/[^\s<>"\']+',
            ]

            for pattern in url_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    # 如果是分组匹配（如video标签），取第一个分组
                    url = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    logger.info(f"[Video] 成功提取视频URL: {url}")
                    return url

            # 如果在content中没找到，检查annotations
            annotations = message.get("annotations", [])
            if annotations:
                logger.debug(f"[Video] 检查annotations: {annotations}")
                for annotation in annotations:
                    if isinstance(annotation, str):
                        for pattern in url_patterns:
                            match = re.search(pattern, annotation, re.IGNORECASE)
                            if match:
                                url = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                                logger.info(f"[Video] 从annotations提取视频URL: {url}")
                                return url

            # 检查reference_id（可能包含视频ID）
            reference_id = message.get("reference_id")
            if reference_id:
                logger.info(f"[Video] 使用reference_id构建URL: {reference_id}")
                return f"https://grok.com/imagine/{reference_id}"

        logger.warning("[Video] 未能从响应中提取视频URL")
        return None

    except Exception as e:
        logger.error(f"[Video] 提取视频URL失败: {e}")
        return None
