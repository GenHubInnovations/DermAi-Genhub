from flask import Blueprint, request, jsonify
from database import MongoDB
import logging
import json
from flask_cors import cross_origin
import base64

logger = logging.getLogger(__name__)

blog_bp = Blueprint('blog', __name__)
db = MongoDB()

@blog_bp.route('/posts', methods=['GET', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def get_posts():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        limit = int(request.args.get('limit', 10))
        skip = int(request.args.get('skip', 0))
        
        posts = db.get_blog_posts(limit, skip)
        return jsonify({"success": True, "posts": posts}), 200
        
    except Exception as e:
        logger.error(f"Error fetching blog posts: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@blog_bp.route('/posts/<post_id>', methods=['GET', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def get_post(post_id):
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        post = db.get_blog_post(post_id)
        
        if post:
            return jsonify({"success": True, "post": post}), 200
        else:
            return jsonify({"success": False, "message": "Post not found"}), 404
        
    except Exception as e:
        logger.error(f"Error fetching blog post: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@blog_bp.route('/posts', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def create_post():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ['title', 'content', 'author_id', 'author_name']):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        title = data['title']
        content = data['content']
        author_id = data['author_id']
        author_name = data['author_name']
        image_data = data.get('image_data')  # Optional
        
        # Basic validation
        if not title or not content:
            return jsonify({"success": False, "message": "Title and content cannot be empty"}), 400
        
        # Create blog post
        success, result = db.create_blog_post(title, content, author_id, author_name, image_data)
        
        if success:
            return jsonify({"success": True, "message": "Blog post created successfully", "post_id": result}), 201
        else:
            return jsonify({"success": False, "message": result}), 400
        
    except Exception as e:
        logger.error(f"Error creating blog post: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@blog_bp.route('/posts/<post_id>', methods=['PUT', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def update_post(post_id):
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ['title', 'content']):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        
        title = data['title']
        content = data['content']
        image_data = data.get('image_data')  # Optional
        
        # Basic validation
        if not title or not content:
            return jsonify({"success": False, "message": "Title and content cannot be empty"}), 400
        
        # Update blog post
        success = db.update_blog_post(post_id, title, content, image_data)
        
        if success:
            return jsonify({"success": True, "message": "Blog post updated successfully"}), 200
        else:
            return jsonify({"success": False, "message": "Failed to update blog post"}), 400
        
    except Exception as e:
        logger.error(f"Error updating blog post: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@blog_bp.route('/posts/<post_id>', methods=['DELETE', 'OPTIONS'])
@cross_origin(origins=["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"], 
              methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
              allow_headers=["Content-Type", "Authorization"],
              supports_credentials=True)
def delete_post(post_id):
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        success = db.delete_blog_post(post_id)
        
        if success:
            return jsonify({"success": True, "message": "Blog post deleted successfully"}), 200
        else:
            return jsonify({"success": False, "message": "Failed to delete blog post"}), 400
        
    except Exception as e:
        logger.error(f"Error deleting blog post: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500 