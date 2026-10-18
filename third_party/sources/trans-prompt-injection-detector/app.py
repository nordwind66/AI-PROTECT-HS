"""Flask web UI for prompt injection detector."""
from __future__ import annotations

import os
import time
import logging
from collections import defaultdict

from flask import Flask, render_template, request, jsonify, g

from config import DEFAULT_MODELS, PROVIDER_ENDPOINTS, DetectorConfig
from llm_detector import LLMDetector, hybrid_detect
from prompt_injection_detector import detect_injection

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# --- Rate limiter (simple in-memory, per-IP) ---
_rate_window = 60  # seconds
_rate_limits: dict[str, dict[str, int | float]] = {
    "regex":  {"max": 30, "window": _rate_window},
    "llm":    {"max": 5,  "window": _rate_window},
    "hybrid": {"max": 5,  "window": _rate_window},
}
_rate_state: dict[str, dict[str, list[float]]] = defaultdict(
    lambda: {"regex": [], "llm": [], "hybrid": []}
)


def _check_rate_limit(ip: str, method: str) -> tuple[bool, str | None]:
    limit = _rate_limits.get(method)
    if limit is None:
        return True, None
    now = time.time()
    window = limit["window"]
    timestamps = _rate_state[ip][method]
    # Prune old entries
    timestamps[:] = [t for t in timestamps if now - t < window]
    if len(timestamps) >= limit["max"]:
        retry_after = int(window - (now - timestamps[0]))
        return False, f"Rate limit exceeded. Retry in {retry_after}s."
    timestamps.append(now)
    return True, None


# --- Security headers ---
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


def _build_config(
    api_key: str, provider: str, endpoint: str | None, model: str | None
) -> DetectorConfig:
    config = DetectorConfig()
    config.llm_api_key = api_key
    config.llm_provider = provider
    if endpoint:
        config.llm_endpoint = endpoint
    if model:
        config.llm_model = model
    if provider in PROVIDER_ENDPOINTS and not endpoint:
        config.llm_endpoint = PROVIDER_ENDPOINTS[provider]
    if provider in DEFAULT_MODELS and not model:
        config.llm_model = DEFAULT_MODELS.get(provider, "")
    return config


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"ok": True, "version": "1.0.0"})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    # Rate limiting
    ip = request.remote_addr or "127.0.0.1"
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    text = (data.get("text") or "").strip()
    method = data.get("method", "regex")

    if not text:
        return jsonify({"ok": False, "error": "请输入检测文本"}), 400

    if method not in ("regex", "llm", "hybrid"):
        return jsonify({"ok": False, "error": f"Unknown method: {method}"}), 400

    allowed, rate_error = _check_rate_limit(ip, method)
    if not allowed:
        return jsonify({"ok": False, "error": rate_error}), 429

    try:
        if method == "regex":
            result = detect_injection(text)
            return jsonify({"ok": True, "method": "regex", "result": result})

        api_key = (data.get("api_key") or "").strip()
        provider = (data.get("provider") or "deepseek").strip()
        endpoint = (data.get("endpoint") or "").strip() or None
        model = (data.get("model") or "").strip() or None

        if not api_key:
            return jsonify({"ok": False, "error": "请先填写 API Key"}), 400

        config = _build_config(api_key, provider, endpoint, model)

        if method == "llm":
            detector = LLMDetector(config)
            result = detector.detect(text)
            result.pop("cached", None)
            # Enrich with regex details if attack detected and LLM didn't error
            if result.get("is_attack") and result.get("risk_level") != "error":
                regex_result = detect_injection(text)
                result["matched_details"] = regex_result.get("matched_details", [])
                result["matched_rules"] = list(set(
                    result.get("matched_rules", []) + regex_result.get("matched_rules", [])
                ))
                result["score"] = max(result.get("score", 0), regex_result.get("score", 0))
            elif result.get("risk_level") == "error":
                # Run regex as fallback when LLM fails
                regex_result = detect_injection(text)
                result = {
                    **result,
                    "matched_details": regex_result.get("matched_details", []),
                    "matched_rules": regex_result.get("matched_rules", []),
                    "score": regex_result.get("score", 0),
                    "risk_level": regex_result.get("risk_level", "low"),
                    "is_attack": regex_result.get("is_attack", False),
                    "reason": f"{result['reason']} — Fallback to regex: {regex_result['reason']}",
                }
            return jsonify({"ok": True, "method": "llm", "result": result})

        llm = LLMDetector(config)
        result = hybrid_detect(text, detect_injection, llm, config)
        result.pop("cached", None)
        return jsonify({"ok": True, "method": "hybrid", "result": result})

    except Exception:
        app.logger.exception("Detection failed")
        return jsonify({
            "ok": False,
            "error": "Detection service error — please try again later.",
        }), 500


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="127.0.0.1",
        port=5000,
    )
