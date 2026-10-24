"""Read-only upstream-compatible inspection history routes."""
from flask import jsonify, request, render_template
from core import db


def register_inspection_history(app):
    def page_offset():
        page = int(request.args.get("page", "1"))
        if not 1 <= page <= 1 + (2**63 - 1) // 20:
            raise ValueError("page out of range")
        return (page - 1) * 20

    @app.get("/api/accounts/inspections")
    def api_account_inspections():
        try:
            offset = page_offset()
        except (TypeError, ValueError):
            return jsonify(ok=False, error="page必须为有效的正整数"), 400
        return jsonify(ok=True, **db.list_account_inspections(limit=20, offset=offset))

    @app.get("/api/accounts/inspections/<int:inspection_id>/failures")
    def api_account_inspection_failures(inspection_id):
        try:
            offset = page_offset()
        except (TypeError, ValueError):
            return jsonify(ok=False, error="page必须为有效的正整数"), 400
        result = db.list_account_inspection_failures(inspection_id, limit=20, offset=offset)
        if result is None:
            return jsonify(ok=False, error="巡检任务不存在"), 404
        return jsonify(ok=True, **result)

    @app.get("/account-inspections")
    def account_inspection_history():
        return render_template("inspection_history.html")
