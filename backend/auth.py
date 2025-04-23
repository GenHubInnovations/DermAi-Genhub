from flask import Blueprint, request, jsonify
import logging
from database import MongoDB
import re
import json
from flask_cors import cross_origin
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)
db = MongoDB()

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def register():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ['email', 'password', 'name']):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        email = data['email']
        password = data['password']
        name = data['name']
        
        # Basic validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"success": False, "message": "Invalid email format"}), 400
        
        if len(password) < 6:
            return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
        
        # Register user
        success, result = db.register_user(email, password, name)
        
        if success:
            return jsonify({"success": True, "message": "Registration successful", "user_id": result}), 201
        else:
            return jsonify({"success": False, "message": result}), 400
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ['email', 'password']):
            return jsonify({"success": False, "message": "Missing email or password"}), 400
        
        email = data['email']
        password = data['password']
        
        # Authenticate user
        success, result = db.login_user(email, password)
        
        if success:
            return jsonify({
                "success": True, 
                "message": "Login successful",
                "token": result["token"],
                "user": result["user"]
            }), 200
        else:
            return jsonify({"success": False, "message": result}), 401
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@auth_bp.route('/verify-token', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def verify_token():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        data = request.get_json()
        
        if not data or 'token' not in data:
            return jsonify({"success": False, "message": "Token not provided"}), 400
        
        token = data['token']
        
        # Verify token
        success, result = db.verify_token(token)
        
        if success:
            return jsonify({
                "success": True,
                "user": result
            }), 200
        else:
            return jsonify({"success": False, "message": result}), 401
        
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@auth_bp.route('/user-predictions', methods=['GET', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def get_user_predictions():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "Authorization token not provided"}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token and get user data
        success, user_data = db.verify_token(token)
        
        if not success:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
            
        # Get user predictions using email from user data
        predictions = db.get_user_predictions(user_data['email'])
        
        # Convert ObjectId to string for JSON serialization
        serialized_predictions = []
        for pred in predictions:
            pred_dict = pred.copy()
            # Convert image_id from ObjectId to string if it exists
            if 'image_id' in pred_dict:
                pred_dict['image_id'] = str(pred_dict['image_id'])
            # Convert timestamp to ISO format string if it's a datetime object
            if 'timestamp' in pred_dict and isinstance(pred_dict['timestamp'], datetime):
                pred_dict['timestamp'] = pred_dict['timestamp'].isoformat()
            serialized_predictions.append(pred_dict)
        
        return jsonify({
            "success": True,
            "predictions": serialized_predictions
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching user predictions: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@auth_bp.route('/store-prediction', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def store_prediction():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "Authorization token not provided"}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        success, user_data = db.verify_token(token)
        
        if not success:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
        # Get prediction data from request body
        data = request.get_json()
        
        if not data or not all(k in data for k in ['email', 'image_id', 'predictions', 'timestamp']):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        # Store prediction under user profile
        success = db.store_user_prediction(
            data['email'],
            data['image_id'],
            data['predictions'],
            data['timestamp']
        )
        
        return jsonify({
            "success": True,
            "message": "Prediction stored successfully"
        }), 201
        
    except Exception as e:
        logger.error(f"Error storing prediction: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@auth_bp.route('/store-feedback', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def store_feedback():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "Authorization token not provided"}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        success, user_data = db.verify_token(token)
        
        if not success:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
        # Get feedback data from request body
        data = request.get_json()
        
        if not data or not all(k in data for k in ['rating', 'description']):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        # Store feedback
        feedback_id = db.store_feedback(
            user_data['email'],
            data['rating'],
            data['description'],
            data.get('prediction_id')  # Optional
        )
        
        return jsonify({
            "success": True,
            "message": "Feedback stored successfully",
            "feedback_id": feedback_id
        }), 201
        
    except Exception as e:
        logger.error(f"Error storing feedback: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@auth_bp.route('/user-feedback', methods=['GET', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def get_user_feedback():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "Authorization token not provided"}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        success, user_data = db.verify_token(token)
        
        if not success:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
        # Get limit from query parameters
        limit = int(request.args.get('limit', 10))
        
        # Get user's feedback
        feedback = db.get_user_feedback(user_data['email'], limit)
        
        return jsonify({
            "success": True,
            "feedback": feedback
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching user feedback: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@auth_bp.route('/users', methods=['GET'])
@cross_origin()
def get_users():
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'No token provided'}), 401
        
        token = auth_header.split(' ')[1]
        is_valid, user_data = db.verify_token(token)
        
        if not is_valid or user_data.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        # Get all users with their predictions and feedback counts
        users = list(db.db[Config.USERS_COLLECTION].find({}, {
            'password': 0,  # Exclude password
            'session_token': 0,  # Exclude session token
            'token_expires': 0  # Exclude token expiry
        }))
        
        # Convert ObjectId to string for JSON serialization
        for user in users:
            user['_id'] = str(user['_id'])
            if 'predictions' in user:
                for pred in user['predictions']:
                    if 'image_id' in pred:
                        pred['image_id'] = str(pred['image_id'])
        
        return jsonify({
            'success': True,
            'users': users
        })
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@auth_bp.route('/feedbacks', methods=['GET'])
@cross_origin()
def get_feedbacks():
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'No token provided'}), 401
        
        token = auth_header.split(' ')[1]
        is_valid, user_data = db.verify_token(token)
        
        if not is_valid or user_data.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        # Get all feedbacks
        feedbacks = list(db.db[Config.FEEDBACK_COLLECTION].find().sort('timestamp', -1))
        
        # Convert ObjectId to string for JSON serialization
        for feedback in feedbacks:
            feedback['_id'] = str(feedback['_id'])
            if 'prediction_id' in feedback:
                feedback['prediction_id'] = str(feedback['prediction_id'])
        
        return jsonify({
            'success': True,
            'feedbacks': feedbacks
        })
    except Exception as e:
        logger.error(f"Error fetching feedbacks: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500 