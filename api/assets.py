"""
API Routes - Assets
GET   /api/assets          → saare assets
GET   /api/assets/<id>     → ek asset
POST  /api/assets          → naya asset
PATCH /api/assets/<id>     → update asset
"""
 
from flask import Blueprint, request, jsonify
from models.database import Asset
from extensions import get_session
 
assets_bp = Blueprint("assets", __name__)
 
 
@assets_bp.route("/assets", methods=["GET"])
def get_assets():
    session = get_session()
    try:
        criticality = request.args.get("criticality")
        asset_type  = request.args.get("asset_type")
 
        query = session.query(Asset).order_by(Asset.risk_score.desc())
 
        if criticality:
            query = query.filter(Asset.criticality == criticality.upper())
        if asset_type:
            query = query.filter(Asset.asset_type == asset_type.lower())
 
        assets = query.all()
        return jsonify({
            "success": True,
            "count":   len(assets),
            "data":    [a.to_dict() for a in assets],
        })
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@assets_bp.route("/assets/<int:asset_id>", methods=["GET"])
def get_asset(asset_id):
    session = get_session()
    try:
        asset = session.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return jsonify({"success": False, "error": "Asset not found"}), 404
        return jsonify({"success": True, "data": asset.to_dict()})
    finally:
        session.close()
 
 
@assets_bp.route("/assets", methods=["POST"])
def create_asset():
    session = get_session()
    try:
        data = request.get_json(force=True)
 
        if not data.get("ip_address"):
            return jsonify({"success": False, "error": "ip_address is required"}), 400
 
        # Duplicate check
        existing = session.query(Asset).filter(
            Asset.ip_address == data["ip_address"]
        ).first()
        if existing:
            return jsonify({"success": False, "error": "IP already exists"}), 409
 
        asset = Asset(
            ip_address  = data["ip_address"],
            hostname    = data.get("hostname"),
            mac_address = data.get("mac_address"),
            os_type     = data.get("os_type"),
            asset_type  = data.get("asset_type", "workstation"),
            criticality = data.get("criticality", "MEDIUM").upper(),
            owner       = data.get("owner"),
            department  = data.get("department"),
            location    = data.get("location"),
            open_ports  = data.get("open_ports", []),
            tags        = data.get("tags", []),
            notes       = data.get("notes"),
        )
        session.add(asset)
        session.commit()
        return jsonify({"success": True, "data": asset.to_dict()}), 201
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()
 
 
@assets_bp.route("/assets/<int:asset_id>", methods=["PATCH"])
def update_asset(asset_id):
    session = get_session()
    try:
        asset = session.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return jsonify({"success": False, "error": "Asset not found"}), 404
 
        data = request.get_json(force=True)
        for field in ["hostname", "os_type", "asset_type", "criticality",
                      "owner", "department", "location", "notes", "tags", "open_ports"]:
            if field in data:
                setattr(asset, field, data[field])
 
        session.commit()
        return jsonify({"success": True, "data": asset.to_dict()})
    except Exception as ex:
        session.rollback()
        return jsonify({"success": False, "error": str(ex)}), 500
    finally:
        session.close()