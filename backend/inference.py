import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import io
import base64
from PIL import Image
import gc
import logging
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load model
try:
    model = load_model(Config.MODEL_PATH)
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {str(e)}")
    model = None

# Class labels
CLASS_LABELS = [
    'Acne and Rosacea Photos',
    'Actinic Keratosis Basal Cell Carcinoma and other Malignant Lesions',
    'Atopic Dermatitis Photos',
    'Eczema Photos',
    'Hair Loss Photos Alopecia and other Hair Diseases',
    'Herpes HPV and other STDs Photos',
    'Light Diseases and Disorders of Pigmentation',
    'Melanoma Skin Cancer Nevi and Moles',
    'Nail Fungus and other Nail Disease',
    'Psoriasis pictures Lichen Planus and related diseases',
    'Scabies Lyme Disease and other Infestations and Bites',
    'Tinea Ringworm Candidiasis and other Fungal Infections',
    'Vascular Tumors',
    'Vasculitis Photos'
]

def preprocess_image(file_bytes):
    """Preprocess image for model prediction"""
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img = img.resize((224, 224))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array /= 255.0
        return img_array
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        return None

def predict_image(file_bytes):
    """Make a prediction on the input image"""
    if not model:
        return {'error': 'Model not loaded'}, 500
    
    img_array = preprocess_image(file_bytes)
    if img_array is None:
        return {'error': 'Invalid image format'}, 400
    
    try:
        predictions = model.predict(img_array, verbose=0)
        predicted_class = np.argmax(predictions, axis=1)[0]
        predicted_label = CLASS_LABELS[predicted_class]
        confidence = float(predictions[0][predicted_class])
        
        # Clear memory
        del img_array, predictions
        gc.collect()
        
        return {
            'prediction': predicted_label,
            'confidence': confidence
        }
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return {'error': 'Prediction failed'}, 500
