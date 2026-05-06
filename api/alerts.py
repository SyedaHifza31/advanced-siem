from flask import Blueprint, request, jsonify
from models.database import Alert
from extensions import get_session
 
alerts_bp = Blueprint("alerts", __name__)
 
VALID_STATUSES = {"OPEN", "ACK", "CLOSED", "FP"}
 
 
@alerts_bp.route("/alerts", methods=["GET"])
def get_alerts():
    session = get_session()
    try:
        limit    = request.args.get("limit", 50, type=int)
        offset   = request.args.get("offset", 0, type=int)
        status   = request.args.get("status")
        severity = request.args.get("severity")
 
        query = session.query(Alert).order_by(Alert.timestamp.desc())
 
        if status:
            query = query.filter(Alert.status == status.upper())
        if severity:
            query = query.filter(Alert.severity == severity.upper())
 
        alerts = query.offset(offset).limit(limit).all()
        total  = session.query(Alert).count()
 
        return jsonify({
            "success": True,
            "total":   total,
            "count":   len(alerts),
            "data":    [a.to_dict() for a in alerts],
        })
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@alerts_bp.route("/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    session = get_session()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({"success": False, "error": "Alert not found"}), 404
        return jsonify({"success": True, "data": alert.to_dict()})
    finally:
        session.close()
 
 
@alerts_bp.route("/alerts", methods=["POST"])
def create_alert():
    session = get_session()
    try:
        data  = request.get_json(force=True)
 
        if not data.get("title"):
            return jsonify({"success": False, "error": "title is required"}), 400
 
        alert = Alert(
            title         = data["title"],
            description   = data.get("description"),
            severity      = data.get("severity", "MEDIUM").upper(),
            severity_num  = data.get("severity_num", 3),
            rule_id       = data.get("rule_id"),
            rule_name     = data.get("rule_name"),
            category      = data.get("category"),
            source_ip     = data.get("source_ip"),
            dest_ip       = data.get("dest_ip"),
            hostname      = data.get("hostname"),
            username      = data.get("username"),
            mitre_tactic  = data.get("mitre_tactic"),
            mitre_tech    = data.get("mitre_tech"),
            ioc_list      = data.get("ioc_list", []),
            tags          = data.get("tags", []),
            status        = "OPEN",
        )
        session.add(alert)
        session.commit()
        return jsonify({"success": True, "data": alert.to_dict()}), 201
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@alerts_bp.route("/alerts/<int:alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    session = get_session()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({"success": False, "error": "Alert not found"}), 404
 
        data = request.get_json(force=True)
 
        if "status" in data:
            new_status = data["status"].upper()
            if new_status not in VALID_STATUSES:
                return jsonify({"success": False,
                                "error": f"Invalid status. Must be one of {VALID_STATUSES}"}), 400
            alert.status = new_status
 
        if "analyst_notes" in data:
            alert.analyst_notes = data["analyst_notes"]
 
        if "false_positive" in data:
            alert.false_positive = bool(data["false_positive"])
            if alert.false_positive:
                alert.status = "FP"
 
        session.commit()
        return jsonify({"success": True, "data": alert.to_dict()})
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@alerts_bp.route("/alerts/<int:alert_id>", methods=["DELETE"])
def delete_alert(alert_id):
    session = get_session()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({"success": False, "error": "Alert not found"}), 404
        session.delete(alert)
        session.commit()
        return jsonify({"success": True, "message": f"Alert {alert_id} deleted"})
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
