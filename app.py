from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a secure key
bcrypt = Bcrypt(app)

# MongoDB setup
client = MongoClient("your_mongodb_connection_string")
db = client["chat_app"]  # Database
users_collection = db["users"]  # Users collection
messages_collection = db["messages"]  # Messages collection

# Admin password
ADMIN_PASSWORD = bcrypt.generate_password_hash("PRASHANT").decode('utf-8')

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Check if user already exists
    if users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({"username": username, "password": hashed_password})
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid username or password"}), 401

    session['username'] = username
    return jsonify({"message": "Logged in successfully"}), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    message = data.get('message')
    file = data.get('file')  # Handle file uploads later
    timestamp = datetime.now().isoformat()

    if not message and not file:
        return jsonify({"error": "Message or file is required"}), 400

    # Save message in database
    messages_collection.insert_one({
        "sender": session['username'],
        "receiver": "admin",
        "message": message,
        "file": file,
        "timestamp": timestamp
    })
    return jsonify({"message": "Message sent successfully"}), 201

@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    username = session['username']
    messages = list(messages_collection.find({"sender": username}))
    for message in messages:
        message["_id"] = str(message["_id"])  # Convert ObjectId to string
    return jsonify(messages), 200

@app.route('/admin', methods=['POST'])
def admin_login():
    data = request.json
    password = data.get('password')

    if bcrypt.check_password_hash(ADMIN_PASSWORD, password):
        session['admin'] = True
        return jsonify({"message": "Admin logged in successfully"}), 200
    return jsonify({"error": "Invalid password"}), 401

@app.route('/admin/messages', methods=['GET'])
def admin_get_messages():
    if not session.get('admin'):
        return jsonify({"error": "Unauthorized"}), 401

    messages = list(messages_collection.find())
    for message in messages:
        message["_id"] = str(message["_id"])  # Convert ObjectId to string
    return jsonify(messages), 200

if __name__ == "__main__":
    app.run(debug=True)
