"""
API Routes - Events
GET  /api/events          → saare events
GET  /api/events/<id>     → ek event
POST /api/events          → naya event add karo
DELETE /api/events/<id>   → event delete karo
"""
 
from flask import Blueprint, request, jsonify
from models.database import Event
from extensions import get_session
 
events_bp = Blueprint("events", __name__)
 
 
@events_bp.route("/events", methods=["GET"])
def get_events():
    session = get_session()
    try:
        limit    = request.args.get("limit", 100, type=int)
        offset   = request.args.get("offset", 0, type=int)
        severity = request.args.get("severity")
        category = request.args.get("category")
 
        query = session.query(Event).order_by(Event.timestamp.desc())
 
        if severity:
            query = query.filter(Event.severity == severity.upper())
        if category:
            query = query.filter(Event.category == category.lower())
 
        events = query.offset(offset).limit(limit).all()
        return jsonify({
            "success": True,
            "count":   len(events),
            "data":    [e.to_dict() for e in events],
        })
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@events_bp.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id):
    session = get_session()
    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"success": False, "error": "Event not found"}), 404
        return jsonify({"success": True, "data": event.to_dict()})
    finally:
        session.close()
 
 
@events_bp.route("/events", methods=["POST"])
def create_event():
    session = get_session()
    try:
        data  = request.get_json(force=True)
        event = Event(
            source_ip    = data.get("source_ip"),
            dest_ip      = data.get("dest_ip"),
            source_port  = data.get("source_port"),
            dest_port    = data.get("dest_port"),
            protocol     = data.get("protocol"),
            source_type  = data.get("source_type", "manual"),
            category     = data.get("category", "unknown"),
            severity     = data.get("severity", "INFO"),
            severity_num = data.get("severity_num", 1),
            raw_message  = data.get("raw_message"),
            hostname     = data.get("hostname"),
            username     = data.get("username"),
            tags         = data.get("tags", []),
        )
        session.add(event)
        session.commit()
        return jsonify({"success": True, "data": event.to_dict()}), 201
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@events_bp.route("/events/<int:event_id>", methods=["DELETE"])
def delete_event(event_id):
    session = get_session()
    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"success": False, "error": "Event not found"}), 404
        session.delete(event)
        session.commit()
        return jsonify({"success": True, "message": f"Event {event_id} deleted"})
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()