"""Verification display route."""
from flask import Blueprint, render_template


verification_bp = Blueprint("verification", __name__)


@verification_bp.route("/verification/<int:finding_id>")
def verification_detail(finding_id):
    return render_template("verification.html", finding_id=finding_id)