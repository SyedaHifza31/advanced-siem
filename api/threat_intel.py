"""
API Routes - Threat Intelligence
GET  /api/threat-intel           → saare IOCs
POST /api/threat-intel           → naya IOC add
GET  /api/threat-intel/check     → koi IP/domain threat hai?
"""
 
from flask import Blueprint, request, jsonify
from models.database import ThreatIntel
from extensions import get_session
 
threat_intel_bp = Blueprint("threat_intel", __name__)
 
 
@threat_intel_bp.route("/threat-intel", methods=["GET"])
def get_indicators():
    session = get_session()
    try:
        ioc_type    = request.args.get("ioc_type")
        threat_type = request.args.get("threat_type")
        active_only = request.args.get("active", "true").lower() == "true"
 
        query = session.query(ThreatIntel)
        if active_only:
            query = query.filter(ThreatIntel.active == True)      # noqa: E712
        if ioc_type:
            query = query.filter(ThreatIntel.ioc_type == ioc_type.lower())
        if threat_type:
            query = query.filter(ThreatIntel.threat_type == threat_type.lower())
 
        indicators = query.order_by(ThreatIntel.last_seen.desc()).all()
        return jsonify({
            "success": True,
            "count":   len(indicators),
            "data":    [i.to_dict() for i in indicators],
        })
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@threat_intel_bp.route("/threat-intel", methods=["POST"])
def add_indicator():
    session = get_session()
    try:
        data = request.get_json(force=True)
 
        if not data.get("indicator"):
            return jsonify({"success": False, "error": "indicator is required"}), 400
 
        ioc = ThreatIntel(
            indicator   = data["indicator"],
            ioc_type    = data.get("ioc_type", "ip"),
            threat_type = data.get("threat_type", "unknown"),
            severity    = data.get("severity", "HIGH").upper(),
            confidence  = data.get("confidence", 80),
            source      = data.get("source", "manual"),
            description = data.get("description"),
            tags        = data.get("tags", []),
        )
        session.add(ioc)
        session.commit()
        return jsonify({"success": True, "data": ioc.to_dict()}), 201
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@threat_intel_bp.route("/threat-intel/check", methods=["GET"])
def check_indicator():
    """
    Koi IP ya domain threat list mein hai ya nahi check karo.
    Usage: GET /api/threat-intel/check?indicator=1.2.3.4
    """
    session = get_session()
    try:
        indicator = request.args.get("indicator")
        if not indicator:
            return jsonify({"success": False, "error": "indicator param required"}), 400
 
        match = session.query(ThreatIntel).filter(
            ThreatIntel.indicator == indicator,
            ThreatIntel.active    == True,          # noqa: E712
        ).first()
 
        if match:
            return jsonify({
                "success":    True,
                "is_threat":  True,
                "data":       match.to_dict(),
            })
        return jsonify({"success": True, "is_threat": False, "data": None})
    finally:
        session.close()