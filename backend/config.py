import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # MongoDB Configuration
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    DB_NAME = 'genhub'
    
    # Collections
    IMAGES_COLLECTION = 'skin_images'
    PREDICTIONS_COLLECTION = 'predictions'
    USERS_COLLECTION = 'users'
    BLOGS_COLLECTION = 'blogs'  # New collection for blog posts
    USER_PREDICTIONS_COLLECTION = 'user_predictions'  # Collection for user predictions with recommendations
    FEEDBACK_COLLECTION = 'feedback'
    CONTACT_MESSAGES_COLLECTION = 'contact_messages'  # Collection for contact form messages
    
    # Model Configuration
    # MODEL_PATH = os.path.join('model', 'web_based_model_50.h5')
    MODEL_PATH = os.path.join('model', 'dermnet_model.pth')
    
    # Upload Configuration
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # CORS Configuration
    CORS_ORIGINS = [
        'https://genhub-frontend.vercel.app',
        'http://localhost:3000',
        'http://localhost:5173',
        'https://genhub-backend.onrender.com'
    ]
    
    # Gunicorn Configuration
    WORKERS = 2
    TIMEOUT = 120  # 2 minutes timeout
    WORKER_CLASS = 'gthread'
    THREADS = 4 