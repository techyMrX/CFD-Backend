from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import face_recognition
import numpy as np
from PIL import Image
import io
from werkzeug.utils import secure_filename
import cv2
from deepface import DeepFace
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import logging

app = Flask(__name__)
# Simple CORS configuration
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///safetynet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

# Create uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# Add this at the top with other configurations
ADMIN_PASSWORD = "eaglepolice"  # The correct admin password

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Twilio credentials

     # Add your personal number here (different from Twilio number)

# Test Twilio connection at startup
try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    logger.info("Twilio client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Twilio client: {str(e)}")

# Models
class User(db.Model):
    __tablename__ = 'user'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    emergency_contacts = db.relationship('EmergencyContact', backref='user', lazy=True)

class Criminal(db.Model):
    __tablename__ = 'criminal'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    image_path = db.Column(db.String(255), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class EmergencyContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relationship = db.Column(db.String(50), nullable=False)  # e.g., "Family", "Local Police", "Emergency"
    relationship_detail = db.Column(db.String(100))  # e.g., "Brother", "Local Station", "Hospital"

class EmergencyAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # active, resolved

# Add Contact model
class Contact(db.Model):
    __tablename__ = 'contact'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relationship = db.Column(db.String(50))

# Modified token decorator to skip OPTIONS requests
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({}), 200
            
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            return f(current_user, *args, **kwargs)
        except:
            return jsonify({'message': 'Token is invalid'}), 401
    
    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create database and tables
def init_db():
    with app.app_context():
        # Drop all tables first
        db.drop_all()
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")

# Initialize database when running the app
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

# Or you can call init_db() directly
init_db()

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')

        print(f"Registering user with password: {password}")  # Debug log
        print(f"Admin password is: {ADMIN_PASSWORD}")  # Debug log

        if not email or not password or not name:
            return jsonify({'message': 'Missing required fields'}), 400

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already registered'}), 400

        # Check if the password matches admin password
        role = 'user'
        if password == ADMIN_PASSWORD:
            role = 'admin'

        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            role=role
        )
        
        db.session.add(new_user)
        db.session.commit()

        token = jwt.encode({
            'user_id': new_user.id,
            'email': new_user.email,
            'role': new_user.role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'message': 'User registered successfully',
            'email': new_user.email,
            'role': new_user.role,
            'name': new_user.name,
            'token': token
        }), 201

    except Exception as e:
        print(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'An error occurred during registration'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print("Received login data:", data)  # Debug print
        
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Missing email or password'}), 400

        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'message': 'User not found'}), 401

        if check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'email': user.email,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'])

            return jsonify({
                'token': token,
                'email': user.email,
                'role': user.role,
                'name': user.name
            }), 200
        
        return jsonify({'message': 'Invalid password'}), 401

    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug print
        return jsonify({'message': 'An error occurred during login'}), 500

# Move the FaceRecognitionSystem class definition to the top
class FaceRecognitionSystem:
    def __init__(self):
        self.known_face_encodings = []
        self.known_face_names = []
        self.known_face_details = []
        
    def load_criminal_database(self):
        criminals = Criminal.query.all()
        for criminal in criminals:
            try:
                image = face_recognition.load_image_file(criminal.image_path)
                face_encodings = face_recognition.face_encodings(image)
                if face_encodings:
                    self.known_face_encodings.append(face_encodings[0])
                    self.known_face_names.append(criminal.name)
                    self.known_face_details.append(criminal.details)
            except Exception as e:
                print(f"Error loading criminal {criminal.name}: {str(e)}")

# Create the face system instance but don't initialize it yet
face_system = FaceRecognitionSystem()

# This function will run automatically before first request
with app.app_context():
    # Create database tables
    db.create_all()
    # Initialize face recognition system
    face_system = FaceRecognitionSystem()
    face_system.load_criminal_database()
    print("Face recognition system initialized!")

@app.route('/api/identify', methods=['POST'])
@token_required
def identify_criminal(current_user):
    try:
        if 'image' not in request.files:
            return jsonify({'message': 'No image file provided'}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400
            
        if file and allowed_file(file.filename):
            # Save the uploaded file temporarily
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + secure_filename(file.filename))
            file.save(temp_path)
            
            # Get all criminals from database
            criminals = Criminal.query.all()
            matches = []
            
            try:
                # Compare with each criminal's photo
                for criminal in criminals:
                    try:
                        # Verify faces
                        result = DeepFace.verify(
                            img1_path=temp_path,
                            img2_path=criminal.image_path,
                            model_name="VGG-Face",
                            distance_metric="cosine",
                            enforce_detection=False
                        )
                        
                        # If faces match
                        if result['verified']:
                            confidence = (1 - result['distance']) * 100
                            matches.append({
                                'name': criminal.name,
                                'details': criminal.details,
                                'confidence': round(confidence, 2)
                            })
                            
                    except Exception as e:
                        print(f"Error comparing with criminal {criminal.name}: {str(e)}")
                        continue
                        
            finally:
                # Clean up temporary file
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            
            # Sort matches by confidence
            matches.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Print debug information
            print(f"Number of matches found: {len(matches)}")
            for match in matches:
                print(f"Match: {match['name']} with confidence: {match['confidence']}%")
            
            return jsonify({
                'message': 'Image processed successfully',
                'matches': matches
            }), 200
            
    except Exception as e:
        print(f"Error in identify_criminal: {str(e)}")
        return jsonify({'message': f'Error processing image: {str(e)}'}), 500
    
    return jsonify({'message': 'Invalid file type'}), 400

# Emergency routes
@app.route('/api/emergency/contacts', methods=['GET', 'POST'])
@token_required
def emergency_contacts(current_user):
    if request.method == 'GET':
        contacts = EmergencyContact.query.filter_by(user_id=current_user.id).all()
        return jsonify([{
            'id': c.id,
            'name': c.name,
            'phone': c.phone,
            'relationship': c.relationship
        } for c in contacts])
    
    data = request.get_json()
    new_contact = EmergencyContact(
        user_id=current_user.id,
        name=data['name'],
        phone=data['phone'],
        relationship=data.get('relationship', '')
    )
    db.session.add(new_contact)
    db.session.commit()
    
    return jsonify({'message': 'Contact added successfully'}), 201

@app.route('/api/emergency/alert', methods=['POST'])
@token_required
def create_alert(current_user):
    data = request.get_json()
    new_alert = EmergencyAlert(
        user_id=current_user.id,
        latitude=data['latitude'],
        longitude=data['longitude'],
        description=data.get('description', '')
    )
    db.session.add(new_alert)
    db.session.commit()
    
    # Here you would implement notification logic (SMS, email, etc.)
    
    return jsonify({'message': 'Emergency alert created'}), 201

# Admin routes
@app.route('/api/police/add-criminal', methods=['POST'])
@token_required
def add_criminal(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    
    try:
        if 'image' not in request.files:
            return jsonify({'message': 'No image file provided'}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400
            
        if file and allowed_file(file.filename):
            # Secure the filename and save the file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            new_criminal = Criminal(
                name=request.form.get('name'),
                details=request.form.get('details'),
                image_path=filepath,
                added_by=current_user.id
            )
            
            db.session.add(new_criminal)
            db.session.commit()
            
            return jsonify({
                'message': 'Criminal record added successfully',
                'criminal_id': new_criminal.id
            }), 201
            
    except Exception as e:
        print(f"Error adding criminal: {str(e)}")
        return jsonify({'message': f'Error: {str(e)}'}), 500
    
    return jsonify({'message': 'Invalid file type'}), 400

# Route to get criminal images (with proper authorization)
@app.route('/api/criminal-image/<int:criminal_id>', methods=['GET'])
@token_required
def get_criminal_image(current_user, criminal_id):
    criminal = Criminal.query.get_or_404(criminal_id)
    return send_file(criminal.image_path, mimetype='image/jpeg')

# Add these routes
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'name': current_user.name,
        'email': current_user.email,
        'contacts': [{
            'id': c.id,
            'name': c.name,
            'phone': c.phone,
            'relationship': c.relationship
        } for c in contacts]
    })

@app.route('/api/contacts', methods=['POST'])
@token_required
def add_contact(current_user):
    try:
        data = request.get_json()
        new_contact = EmergencyContact(
            user_id=current_user.id,
            name=data['name'],
            phone=data['phone'],
            relationship=data['relationship'],
            relationship_detail=data.get('relationship_detail', '')
        )
        db.session.add(new_contact)
        db.session.commit()
        return jsonify({'message': 'Contact added successfully'}), 201
    except Exception as e:
        print(f"Error adding contact: {str(e)}")
        return jsonify({'message': 'Error adding contact'}), 500

@app.route('/api/contacts', methods=['GET'])
@token_required
def get_contacts(current_user):
    try:
        contacts = EmergencyContact.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            'contacts': [{
                'id': c.id,
                'name': c.name,
                'phone': c.phone,
                'relationship': c.relationship,
                'relationship_detail': c.relationship_detail
            } for c in contacts]
        }), 200
    except Exception as e:
        print(f"Error fetching contacts: {str(e)}")
        return jsonify({'message': 'Error fetching contacts'}), 500

# Add route to refresh face recognition database
@app.route('/api/refresh-database', methods=['POST'])
@token_required
def refresh_database(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    
    try:
        face_system.load_criminal_database()
        return jsonify({'message': 'Face recognition database refreshed successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error refreshing database: {str(e)}'}), 500

# Add this route to check stored criminals
@app.route('/api/criminals', methods=['GET'])
@token_required
def list_criminals(current_user):
    criminals = Criminal.query.all()
    return jsonify({
        'criminals': [{
            'id': c.id,
            'name': c.name,
            'image_path': c.image_path,
            'details': c.details
        } for c in criminals]
    })

# Add this temporary route to reset the database (remove in production)
@app.route('/api/reset-db', methods=['POST'])
def reset_db():
    try:
        db.drop_all()
        db.create_all()
        return jsonify({'message': 'Database reset successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/users', methods=['GET', 'OPTIONS'])
@token_required
def get_users(current_user):
    try:
        if current_user.role != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403
        
        users = User.query.all()
        user_list = [{
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role
        } for user in users]
        
        return jsonify({
            'users': user_list
        }), 200
        
    except Exception as e:
        print(f"Error in get_users: {str(e)}")
        return jsonify({'message': 'Error fetching users'}), 500

# Add this new route to get user contacts
@app.route('/api/users/<int:user_id>/contacts', methods=['GET'])
@token_required
def get_user_contacts(current_user, user_id):
    try:
        if current_user.role != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403
            
        contacts = EmergencyContact.query.filter_by(user_id=user_id).all()
        contact_list = [{
            'id': contact.id,
            'name': contact.name,
            'phone': contact.phone,
            'relationship': contact.relationship,
            'relationship_detail': contact.relationship_detail
        } for contact in contacts]
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        return jsonify({
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role
            },
            'contacts': contact_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching user contacts: {str(e)}")
        return jsonify({'message': 'Error fetching user contacts'}), 500

@app.route('/api/send-location', methods=['POST'])
@token_required
def send_location(current_user):
    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        description = data.get('description', '')

        google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"
        
        message_body = f"""
EMERGENCY ALERT from {current_user.name}!

🚨 Current Location: {google_maps_link}

📝 Description: {description}

This is an automated emergency alert. Please respond immediately!
        """

        try:
            message = twilio_client.messages.create(
                body=message_body,
                from_=TWILIO_PHONE_NUMBER,
                to=RECIPIENT_NUMBER  # Send to a different number
            )
            logger.info(f"Message sent successfully with SID: {message.sid}")
            return jsonify({
                'message': 'Location shared successfully',
                'status': 'success'
            }), 200
            
        except TwilioRestException as e:
            logger.error(f"Twilio error: {str(e)}")
            return jsonify({
                'message': f'Failed to send message: {str(e)}',
                'status': 'error'
            }), 500

    except Exception as e:
        logger.error(f"Error sending location: {str(e)}")
        return jsonify({
            'message': 'Error sending location',
            'status': 'error'
        }), 500
