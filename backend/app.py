from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from werkzeug.utils import secure_filename
import io
from PIL import Image
import base64
import datetime
import torch
import torchvision.transforms as transforms
from torchvision.models import resnet50
import numpy as np
from config import Config
from database import MongoDB
import gc
from auth import auth_bp
from api.blog import blog_bp  # Import the blog blueprint

app = Flask(__name__)
CORS(app, 
     resources={r"/*": {
         "origins": ["https://genhub-frontend.vercel.app", "http://localhost:3000", "http://localhost:5173"],
         "methods": ["GET", "POST", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],
         "supports_credentials": True,
         "expose_headers": ["Content-Type", "X-Requested-With", "X-Auth-Token"]
     }},
     supports_credentials=True)
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize MongoDB
try:
    db = MongoDB()
    logger.info("MongoDB initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize MongoDB: {str(e)}")
    db = None

# Replace your current model loading code with this
model = None
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def get_model():
    global model
    if model is None:
        try:
            # Define model architecture (must match training)
            model_instance = resnet50(weights=None)  # Use weights=None instead of pretrained=False
            num_ftrs = model_instance.fc.in_features
            model_instance.fc = torch.nn.Sequential(
                torch.nn.Linear(num_ftrs, 512),
                torch.nn.ReLU(),
                torch.nn.Dropout(0.5),
                torch.nn.Linear(512, 6)  # 6 classes
            )
            
            # Load trained weights
            model_instance.load_state_dict(torch.load(Config.MODEL_PATH, map_location=device))
            model_instance = model_instance.to(device)
            model_instance.eval()
            return model_instance
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return None
    return model

# Updated class labels to match your new model
CLASS_LABELS = [
    'Autoimmune and Inflammatory Dermatoses',
    'Bullous Disease Photos',
    'Infectious Dermatoses',
    'Inflammatory Dermatoses',
    'Neoplastic Lesions',
    'Pigmentation Hair and Nail Disorders'
]

CATEGORY_HIERARCHY = {
    "Autoimmune and Inflammatory Dermatoses": [
        "Exanthems and Drug Eruptions",
        "Psoriasis pictures Lichen Planus and related diseases",
        "Lupus and other Connective Tissue diseases",
        "Urticaria Hives",
        "Vasculitis Photos",
        "Systemic Disease"
    ],
    "Bullous Disease Photos": ["Bullous Disease Photos"],
    "Infectious Dermatoses": [
        "Cellulitis Impetigo and other Bacterial Infections",
        "Tinea Ringworm Candidiasis and other Fungal Infections",
        "Warts Molluscum and other Viral Infections",
        "Scabies Lyme Disease and other Infestations and Bites"
    ],
    "Inflammatory Dermatoses": [
        "Eczema Photos",
        "Acne and Rosacea Photos",
        "Poison Ivy Photos and other Contact Dermatitis"
    ],
    "Neoplastic Lesions": [
        "Melanoma Skin Cancer Nevi and Moles",
        "Seborrheic Keratoses and other Benign Tumors",
        "Actinic Keratosis Basal Cell Carcinoma and other Malignant Lesions"
    ],
    "Pigmentation Hair and Nail Disorders": [
        "Light Diseases and Disorders of Pigmentation",
        "Hair Loss Photos Alopecia and other Hair Diseases",
        "Nail Fungus and other Nail Disease"
    ]
}

# Define image transformations (must match training)
transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        if not db:
            return jsonify({'error': 'Database connection not available'}), 500
        
        # Load model on demand
        model = get_model()    
        if not model:
            return jsonify({'error': 'Model not loaded'}), 500

        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Allowed types: png, jpg, jpeg'}), 400

        try:
            # Process image
            image_bytes = file.read()
            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            
            # Apply transformations
            img_tensor = transform(img).unsqueeze(0).to(device)
            
            # Make prediction
            with torch.no_grad():
                outputs = model(img_tensor)
                probabilities = torch.nn.functional.softmax(outputs, dim=1)
                top3_conf, top3_indices = torch.topk(probabilities, 3)
            
            # Convert to numpy arrays
            top3_conf = top3_conf.cpu().numpy()[0]
            top3_indices = top3_indices.cpu().numpy()[0]
            
            # Get top 3 predictions with subcategories
            top_predictions = []
            for i in range(3):
                class_idx = top3_indices[i]
                class_label = CLASS_LABELS[class_idx]
                confidence = top3_conf[i]
                subcategories = CATEGORY_HIERARCHY.get(class_label, [])
                top_predictions.append({
                    'label': class_label,
                    'confidence': float(confidence),
                    'subcategories': subcategories
                })

            # Prepare and store image document FIRST
            image_doc = {
                'filename': secure_filename(file.filename),
                'image_data': base64.b64encode(image_bytes).decode('utf-8'),
                'timestamp': datetime.datetime.utcnow()
            }
            image_id = db.store_image(image_doc)  # This must come before prediction_doc

            # Prepare and store prediction document
            prediction_doc = {
                'image_id': image_id,
                'predictions': top_predictions,
                'timestamp': datetime.datetime.utcnow(),
                'class_probabilities': probabilities.cpu().numpy()[0].tolist()
            }
            db.store_prediction(prediction_doc)

            # Cleanup
            del img_tensor
            gc.collect()

            return jsonify({
                'predictions': top_predictions,
                'image_id': image_id
            })

        except Exception as e:
            logger.error(f"Error processing image: {str(e)}")
            return jsonify({'error': f'Error processing image: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/history', methods=['GET'])
def get_history():
    """Get recent prediction history"""
    try:
        limit = int(request.args.get('limit', 10))
        history = db.get_image_history(limit)
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error fetching history: {str(e)}")
        return jsonify({'error': 'Error fetching history'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    status = {
        'status': 'healthy',
        'model_loaded': get_model() is not None,
        'database_connected': db is not None
    }
    return jsonify(status)

@app.route('/contact', methods=['POST'])
def submit_contact():
    """Handle contact form submissions"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'message']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Store the contact message
        message_id = db.store_contact_message(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            message=data['message']
        )
        
        return jsonify({
            'success': True,
            'message': 'Your message has been received. We will get back to you soon.',
            'message_id': message_id
        })
    except Exception as e:
        logger.error(f"Error processing contact form: {str(e)}")
        return jsonify({'error': 'Failed to process your message. Please try again later.'}), 500

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(blog_bp, url_prefix='/blog')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)