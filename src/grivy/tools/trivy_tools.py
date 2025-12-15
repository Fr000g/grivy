import subprocess
import time
from pathlib import Path
from typing import Dict, Optional

from langchain.tools import tool
from pydantic import BaseModel, Field, validator

from grivy.cli.output_handler import summarize_report
from grivy.cli.style import dim_text

# 这里的 Tool 直接调用本地 Trivy CLI，并在 Python 内部做摘要，避免把大 JSON 回传给 LLM。


DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT = 300  # 秒


class _BaseScanInput(BaseModel):
    severity: str = Field(
        default="HIGH,CRITICAL",
        description="漏洞严重级别过滤，逗号分隔，例如 HIGH,CRITICAL",
    )
    ignore_unfixed: bool = Field(
        default=True,
        description="是否忽略尚未有修复的漏洞 (--ignore-unfixed)",
    )
    format: str = Field(
        default="json",
        description="输出格式：json | table | sarif，内部默认 json 便于解析",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="命令超时（秒），避免长时间阻塞",
        ge=30,
        le=1800,
    )
    output_path: Optional[str] = Field(
        default=None,
        description="自定义报告输出路径，默认存储在 data/ 目录",
    )

    @validator("format")
    def validate_format(cls, v: str) -> str:
        allowed = {"json", "table", "sarif"}
        if v not in allowed:
            raise ValueError(f"format 必须是 {allowed}")
        return v


class ImageScanInput(_BaseScanInput):
    image: str = Field(..., description="镜像名，例如 alpine:3.19")


class FsScanInput(_BaseScanInput):
    path: str = Field(..., description="本地目录或文件路径")


class RepoScanInput(_BaseScanInput):
    repo_url_or_path: str = Field(
        ..., description="Git 仓库地址或已克隆的本地路径"
    )


class SbomScanInput(_BaseScanInput):
    sbom_path: str = Field(..., description="本地 SBOM 文件路径")


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _build_output_path(prefix: str, user_defined: Optional[str]) -> Path:
    if user_defined:
        return Path(user_defined)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / f"{prefix}-{_timestamp()}.json"


def _stream_run(cmd: list, timeout: int) -> int:
    """
    以流式方式运行子进程，把 stdout/stderr 直接打印到控制台，防止长时间无输出。
    返回退出码。
    """
    print(dim_text(f"[trivy] 执行命令: {' '.join(cmd)}"))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(dim_text("[trivy] 未找到 trivy 可执行文件，请确认已安装并在 PATH 中。"))
        return -127

    start = time.time()
    try:
        for line in proc.stdout or []:
            print(dim_text(line.rstrip()))
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)
        proc.wait(timeout=max(1, timeout - int(time.time() - start)))
    except subprocess.TimeoutExpired:
        proc.kill()
        print(dim_text(f"[trivy] 扫描超时（>{timeout}s）"))
        return -1
    return proc.returncode


def _summarize(report_path: Path) -> Dict:
    if not report_path.exists():
        return {
            "summary": "报告文件不存在，无法解析",
            "report_path": str(report_path),
        }
    summary = summarize_report(report_path)
    return {
        "summary": summary["summary_text"],
        "high": summary["high"],
        "critical": summary["critical"],
        "top": summary["top"],
        "total_findings": summary["total_findings"],
        "report_path": str(report_path),
    }


@tool
def trivy_image_scan(
    image: str,
    severity: str = "HIGH,CRITICAL",
    ignore_unfixed: bool = True,
    format: str = "json",
    timeout: int = DEFAULT_TIMEOUT,
    output_path: Optional[str] = None,
):
    """扫描容器镜像漏洞

    Args:
        image: 镜像名，例如 alpine:3.19
        severity: 漏洞严重级别过滤，逗号分隔，例如 HIGH,CRITICAL
        ignore_unfixed: 是否忽略尚未有修复的漏洞
        format: 输出格式：json | table | sarif
        timeout: 命令超时（秒），避免长时间阻塞
        output_path: 自定义报告输出路径，默认存储在 data/ 目录
    """
    target = image
    report_path = _build_output_path("image", output_path)
    cmd = [
        "trivy",
        "image",
        "--severity",
        severity,
        "--format",
        format,
        "--output",
        str(report_path),
    ]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(target)
    exit_code = _stream_run(cmd, timeout)
    summary = _summarize(report_path)
    summary["exit_code"] = exit_code
    summary["target"] = target
    return summary


@tool
def trivy_fs_scan(
    path: str,
    severity: str = "HIGH,CRITICAL",
    ignore_unfixed: bool = True,
    format: str = "json",
    timeout: int = DEFAULT_TIMEOUT,
    output_path: Optional[str] = None,
):
    """扫描本地目录/文件漏洞与配置风险

    Args:
        path: 本地目录或文件路径
        severity: 漏洞严重级别过滤，逗号分隔，例如 HIGH,CRITICAL
        ignore_unfixed: 是否忽略尚未有修复的漏洞
        format: 输出格式：json | table | sarif
        timeout: 命令超时（秒），避免长时间阻塞
        output_path: 自定义报告输出路径，默认存储在 data/ 目录
    """
    target = path
    report_path = _build_output_path("fs", output_path)
    cmd = [
        "trivy",
        "fs",
        "--severity",
        severity,
        "--format",
        format,
        "--output",
        str(report_path),
    ]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(target)
    exit_code = _stream_run(cmd, timeout)
    summary = _summarize(report_path)
    summary["exit_code"] = exit_code
    summary["target"] = target
    return summary


@tool
def trivy_repo_scan(
    repo_url_or_path: str,
    severity: str = "HIGH,CRITICAL",
    ignore_unfixed: bool = True,
    format: str = "json",
    timeout: int = DEFAULT_TIMEOUT,
    output_path: Optional[str] = None,
):
    """扫描 Git 仓库（本地或远程）

    Args:
        repo_url_or_path: Git 仓库地址或已克隆的本地路径
        severity: 漏洞严重级别过滤，逗号分隔，例如 HIGH,CRITICAL
        ignore_unfixed: 是否忽略尚未有修复的漏洞
        format: 输出格式：json | table | sarif
        timeout: 命令超时（秒），避免长时间阻塞
        output_path: 自定义报告输出路径，默认存储在 data/ 目录
    """
    target = repo_url_or_path
    report_path = _build_output_path("repo", output_path)
    cmd = [
        "trivy",
        "repo",
        "--severity",
        severity,
        "--format",
        format,
        "--output",
        str(report_path),
    ]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(target)
    exit_code = _stream_run(cmd, timeout)
    summary = _summarize(report_path)
    summary["exit_code"] = exit_code
    summary["target"] = target
    return summary


@tool
def trivy_sbom_scan(
    sbom_path: str,
    severity: str = "HIGH,CRITICAL",
    ignore_unfixed: bool = True,
    format: str = "json",
    timeout: int = DEFAULT_TIMEOUT,
    output_path: Optional[str] = None,
):
    """基于 SBOM 文件进行漏洞检测

    Args:
        sbom_path: 本地 SBOM 文件路径
        severity: 漏洞严重级别过滤，逗号分隔，例如 HIGH,CRITICAL
        ignore_unfixed: 是否忽略尚未有修复的漏洞
        format: 输出格式：json | table | sarif
        timeout: 命令超时（秒），避免长时间阻塞
        output_path: 自定义报告输出路径，默认存储在 data/ 目录
    """
    target = sbom_path
    report_path = _build_output_path("sbom", output_path)
    cmd = [
        "trivy",
        "sbom",
        "--input",
        target,
        "--severity",
        severity,
        "--format",
        format,
        "--output",
        str(report_path),
    ]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    exit_code = _stream_run(cmd, timeout)
    summary = _summarize(report_path)
    summary["exit_code"] = exit_code
    summary["target"] = target
    return summary


@tool
def trivy_help():
    """回答 Trivy 能力与参数的帮助说明，不执行扫描"""
    return (
        "Trivy 支持的目标：image / fs / repo / sbom / k8s（未来迭代）。\n"
        "常用参数：severity(HIGH,CRITICAL)、--ignore-unfixed、--format json|table|sarif、--output、--timeout（本工具额外提供）。\n"
        "缺省策略：severity=HIGH,CRITICAL，ignore_unfixed=True，format=json，timeout=300s，报告存储在 data/ 下。"
    )


def get_tools():
    """供外部创建 Agent 时统一获取工具集合。"""
    # 返回所有 @tool 装饰的函数
    return [
        trivy_image_scan,
        trivy_fs_scan,
        trivy_repo_scan,
        trivy_sbom_scan,
        trivy_help,
    ]
