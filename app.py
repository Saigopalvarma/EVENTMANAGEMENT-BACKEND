from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
import os
from dotenv import load_dotenv
from mongo_client import db,users_collection ,events_collection ,attendees_collection, attendees_details_collection
from qrcode import make as make_qr
import base64
from io import BytesIO
import csv
from flask import Response
from io import StringIO
import requests

# Function to send email using EmailJS
def send_confirmation_email(user_email, event_name, event_place, qr_code_url):
    try:
        # Prepare the email data
        email_data = {
            'service_id': 'service_qzqjxtb',  # Replace with your EmailJS service ID
            'template_id': 'template_6yzu07p',  # Replace with your EmailJS template ID
            'user_id': 'QmqHaF-cBNHGhwREg',  # Replace with your EmailJS user ID
            'template_params': {
                'to_email': user_email,
                'event_name': event_name,
                'event_place': event_place,
                'qr_code_url': qr_code_url
            }
        }
        
        # Send the request to EmailJS API
        response = requests.post(
            'https://api.emailjs.com/api/v1.0/email/send',
            json=email_data
        )
        
        # Check if the email was sent successfully
        if response.status_code == 200:
            print("Email sent successfully!")
        else:
            print(f"Failed to send email: {response.text}")
        
        return response
    except Exception as e:
        print(f"Error sending email: {e}")
        return None



load_dotenv()

from flask_cors import CORS
# Enable CORS for the Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)
bcrypt = Bcrypt(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback_key")
jwt = JWTManager(app)

# MongoDB Atlas connection



# Helper function to serialize MongoDB documents
def serialize_doc(doc):
    doc["_id"] = str(doc["_id"])
    return doc

# Helper function to check user roles
def check_role(required_role):
    def decorator(func):
        @jwt_required()
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = users_collection.find_one({"_id": ObjectId(user_id)})
            if not user or user.get("role") != required_role:
                return jsonify({"error": "Access denied"}), 403
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

# User registration
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, create_access_token
from bson import ObjectId


@app.route("/api/register", methods=["POST"])
def register_user():
    try:
        data = request.json
        print("Registration payload received:", data)

        # Check for required fields
        if not data.get("fullName") or not data.get("email") or not data.get("password") or not data.get("role"):
            return jsonify({"error": "Missing required fields"}), 400

        role = data["role"]

        # Check if non-user role is being registered
        if role != "user":
            try:
                verify_jwt_in_request()
                current_user_id = get_jwt_identity()
                current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})

                if not current_user or current_user["role"] != "admin":
                    return jsonify({"error": "Only admins can register organizers/admins"}), 403

            except Exception as jwt_error:
                print("JWT verification failed:", jwt_error)
                return jsonify({"error": "Only admins can register organizers/admins"}), 403

        # Check for duplicate email
        if users_collection.find_one({"email": data["email"]}):
            return jsonify({"error": "Email already exists"}), 400

        # Hash password
        hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

        # Create user object
        user = {
            "fullName": data["fullName"],
            "email": data["email"],
            "password": hashed_password,
            "role": role
        }

        # Insert user into the DB
        result = users_collection.insert_one(user)
        user_id = str(result.inserted_id)

        # Create access token
        access_token = create_access_token(identity=user_id)

        return jsonify({
            "message": f"{role.capitalize()} registered successfully",
            "access_token": access_token,
            "role": role
        }), 201

    except Exception as e:
        print("Exception in /api/register:", e)
        return jsonify({"error": "Failed to register user"}), 500



# User login
@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.json
    print(f"Login attempt with email: {data['email']}")  # Debugging log

    # Fetch user by email
    user = users_collection.find_one({"email": data["email"]})
    
    if user:
        print(f"User found: {user['email']}")  # Debugging log

        # Check if the password matches
        if bcrypt.check_password_hash(user["password"], data["password"]):
            print("Password matched!")  # Debugging log

            # Generate JWT token
            access_token = create_access_token(identity=str(user["_id"]))

            # Return the token, role, and user's full name
            return jsonify({
                "access_token": access_token,
                "role": user.get("role", "user"),  # Default role is "user"
                "fullName": user.get("fullName", "N/A")  # Include user's full name
            }), 200
        else:
            print("Password mismatch")  # Debugging log
    else:
        print("User not found")  # Debugging log

    return jsonify({"error": "Invalid email or password"}), 401

# Protected route to fetch user details
@app.route("/api/user", methods=["GET"])
@jwt_required()
def get_user():
    # Get the user ID from the JWT token
    user_id = get_jwt_identity()
    
    # Fetch the user from the database using the user ID
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if user:
        # Return the serialized user data
        return jsonify(serialize_doc(user))
    
    return jsonify({"error": "User not found"}), 404


# API to create a new event (Organizer Only)
@app.route("/api/events", methods=["POST"])
@check_role("organizer")  # Ensure only organizers can create events
def create_event():
    data = request.json

    # Validate required fields
    required_fields = ["title", "date", "location", "description", "max_seats"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Ensure max_seats is a positive integer
    if "max_seats" in data:
        try:
            data["max_seats"] = int(data["max_seats"])  # Convert max_seats to an integer
            if data["max_seats"] <= 0:
                return jsonify({"error": "max_seats must be a positive integer"}), 400
        except ValueError:
            return jsonify({"error": "max_seats must be a positive integer"}), 400

    # Set default values
    data["organizer_id"] = get_jwt_identity()  # Associate event with the organizer
    data["current_attendees"] = 0  # Default to 0 attendees

    # Insert the event into the database
    try:
        result = events_collection.insert_one(data)
        return jsonify({"message": "Event created successfully", "event_id": str(result.inserted_id)}), 201
    except Exception as e:
        print(f"Error creating event: {e}")
        return jsonify({"error": "Failed to create event"}), 500

# API to update an event (Organizer Only)
@app.route("/api/events/<event_id>", methods=["PUT"])
@check_role("organizer")
def update_event(event_id):
    try:
        organizer_id = get_jwt_identity()
        print(f"Organizer ID from Token: {organizer_id}")  # Debugging log
        print(f"Event ID: {event_id}")  # Debugging log

        # Validate the event ID
        try:
            event_id = ObjectId(event_id)
        except InvalidId:
            return jsonify({"error": "Invalid event ID"}), 400

        # Check if the event exists and is owned by the organizer
        event = events_collection.find_one({"_id": event_id, "organizer_id": organizer_id})
        print(f"Event Found: {event}")  # Debugging log
        if not event:
            return jsonify({"error": "Event not found or access denied"}), 404

        # Update the event
        data = request.json
        print(f"Update Data: {data}")  # Debugging log

        # Validate and convert max_seats if present
        if "max_seats" in data:
            try:
                data["max_seats"] = int(data["max_seats"])
                if data["max_seats"] <= 0:
                    return jsonify({"error": "max_seats must be a positive integer"}), 400
            except Exception as e:
                print(f"Error converting max_seats: {e}")
                return jsonify({"error": "max_seats must be a positive integer"}), 400

        # Remove fields that should not be updated
        data.pop("_id", None)
        data.pop("organizer_id", None)
        data.pop("current_attendees", None)

        try:
            result = events_collection.update_one({"_id": event_id, "organizer_id": organizer_id}, {"$set": data})
            if result.modified_count == 1:
                print(f"Event updated successfully for Event ID: {event_id}")
                return jsonify({"message": "Event updated successfully"}), 200
            else:
                print("No changes made to the event.")
                return jsonify({"message": "No changes made to the event."}), 200
        except Exception as e:
            print(f"Error updating event: {e}")
            return jsonify({"error": "Failed to update event"}), 500
    except Exception as e:
        print(f"Error updating event: {e}")  # Log the error
        return jsonify({"error": "Failed to update event"}), 500

# API to delete an event (Organizer Only)
@app.route("/api/events/<event_id>", methods=["DELETE"])
@check_role("organizer")
def delete_event(event_id):
    organizer_id = get_jwt_identity()
    event = events_collection.find_one({"_id": ObjectId(event_id), "organizer_id": organizer_id})
    if not event:
        return jsonify({"error": "Event not found or access denied"}), 404
    events_collection.delete_one({"_id": ObjectId(event_id)})
    return jsonify({"message": "Event deleted successfully"}), 200

# API to fetch all events
@app.route("/api/events", methods=["GET"])
def get_events():
    events = list(events_collection.find())
    return jsonify([serialize_doc(event) for event in events])

# API to fetch event details by ID
@app.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id):
    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if event:
        return jsonify(serialize_doc(event))
    return jsonify({"error": "Event not found"}), 404

# API to register a user for an event
from qrcode import make as make_qr
import base64
from io import BytesIO

# API to register a user for an event
@app.route("/api/events/<event_id>/register", methods=["POST"])
@jwt_required()
def register_user_for_event(event_id):
    try:
        user_id = get_jwt_identity()

        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401

        # Fetch the event
        event = events_collection.find_one({"_id": ObjectId(event_id)})
        if not event:
            return jsonify({"error": "Event not found"}), 404

        # Prevent organizer from registering for their own event
        if str(event.get("organizer_id")) == str(user_id):
            return jsonify({"error": "Organizers cannot register for their own event."}), 400

        # Check if already registered
        existing_registration = attendees_collection.find_one({"event_id": event_id, "user_id": user_id})
        if existing_registration:
            return jsonify({"error": "You have already registered for this event."}), 400

        # Check event capacity
        if event["current_attendees"] >= event["max_seats"]:
            return jsonify({"error": "Event is fully booked"}), 400

        # Generate QR code containing user_id and event_id
        qr_data = f"user_id:{user_id}|event_id:{event_id}"
        qr_image = make_qr(qr_data)
        buffered = BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
        qr_code_url = f"data:image/png;base64,{qr_code_base64}"

        # Insert attendee record
        attendee = {
            "event_id": event_id,
            "user_id": user_id,
            "qr_code": qr_code_url
        }
        attendees_collection.insert_one(attendee)

        # Update event attendee count
        events_collection.update_one(
            {"_id": ObjectId(event_id)},
            {"$inc": {"current_attendees": 1}}
        )

        # Return qr_code_url in the response so the frontend can use it
        return jsonify({"message": "Successfully registered for the event", "qr_code_url": qr_code_url}), 200

    except Exception as e:
        import traceback
        print("❌ Error registering user:")
        traceback.print_exc()  # this gives a full traceback
        return jsonify({"error": "Failed to register for event"}), 500





# API to fetch attendees for an event
@app.route("/api/events/<event_id>/attendees", methods=["GET"])
@check_role("organizer")
def get_attendees(event_id):
    attendees = list(attendees_collection.find({"event_id": event_id}))
    attendee_details = []
    for attendee in attendees:
        user = users_collection.find_one({"_id": ObjectId(attendee["user_id"])})
        if user:
            attendee_details.append({
                "_id": str(attendee["_id"]),
                "fullName": user.get("fullName", ""),
                "email": user.get("email", "")
            })
    return jsonify(attendee_details)

# API to fetch all users (Admin Only)
@app.route("/api/users", methods=["GET"])
@check_role("admin")
def get_all_users():
    users = list(users_collection.find())
    return jsonify([serialize_doc(user) for user in users])

# API to fetch all events (Admin Only)
@app.route("/api/admin/events", methods=["GET"])
@check_role("admin")
def get_all_events():
    events = list(events_collection.find())
    return jsonify([serialize_doc(event) for event in events])

# API to fetch registered events for a user
@app.route("/api/user/registered-events", methods=["GET"])
@jwt_required()
def get_registered_events():
    try:
        user_id = get_jwt_identity()
        print(f"Fetching registered events for user: {user_id}")  # Debugging log

        # Fetch all events the user has registered for
        registered_events = list(attendees_collection.find({"user_id": user_id}))
        events_with_qr = []

        for attendee in registered_events:
            event = events_collection.find_one({"_id": ObjectId(attendee["event_id"])})
            if event:
                events_with_qr.append({
                    "event_title": event["title"],
                    "event_date": event["date"],
                    "event_location": event["location"],
                    "qr_code": attendee["qr_code"]
                })

        return jsonify(events_with_qr), 200
    except Exception as e:
        print(f"Error fetching registered events: {e}")
        return jsonify({"error": "Failed to fetch registered events"}), 500

# API to fetch events created by the organizer
@app.route("/api/organizer/events", methods=["GET"])
@check_role("organizer")  # Ensure only organizers can access this endpoint
def get_organizer_events():
    organizer_id = get_jwt_identity()  # Get the organizer's ID from the token
    events = list(events_collection.find({"organizer_id": organizer_id}))
    return jsonify([serialize_doc(event) for event in events]), 200

# Delete a user (Admin Only)
@app.route("/api/users/<user_id>", methods=["DELETE"])
@check_role("admin")
def delete_user(user_id):
    try:
        result = users_collection.delete_one({"_id": ObjectId(user_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete user"}), 500

# # Delete an event (Admin Only)
@app.route("/api/admin/events/<event_id>", methods=["DELETE"])
@check_role("admin")
def ADMIN_delete_event(event_id):
    try:
        result = events_collection.delete_one({"_id": ObjectId(event_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Event deleted successfully"}), 200
        else:
            return jsonify({"error": "Event not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete event"}), 500


@app.route("/api/events/<event_id>/attendees/export", methods=["GET"])
@jwt_required()
def export_attendees(event_id):
    try:
        event = events_collection.find_one({"_id": ObjectId(event_id)})
        if not event:
            return jsonify({"error": "Event not found"}), 404

        user_id = get_jwt_identity()
        if str(event["organizer_id"]) != str(user_id):
            return jsonify({"error": "Unauthorized"}), 403

        attendees = list(attendees_collection.find({"event_id": event_id}))

        csv_file = StringIO()
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["User ID", "Name", "Email", "QR Code"])  # Updated Header

        for attendee in attendees:
            user = users_collection.find_one({"_id": ObjectId(attendee["user_id"])})
            name = user.get("fullName", "N/A") if user else "N/A"
            email = user.get("email", "N/A") if user else "N/A"
            qr_code = attendee.get("qr_code", "")
            csv_writer.writerow([attendee["user_id"], name, email, qr_code])

        csv_output = csv_file.getvalue()
        csv_file.close()

        return Response(
            csv_output,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment;filename=attendees_event_{event_id}.csv"
            },
        )
    except Exception as e:
        print(f"Error exporting attendees: {e}")
        return jsonify({"error": "Failed to export attendees"}), 500
# ----------------------------------------------


@app.route('/api/events/<event_id>/attendee-details', methods=['POST'])
@jwt_required()
def store_attendee_details(event_id):
    current_user = get_jwt_identity()  # Logged-in user's email
    data = request.get_json()

    profession = data.get('profession')
    college = data.get('college')
    year_of_passing = data.get('yearOfPassing')
    reason_for_interest = data.get('reasonForInterest')

    if not profession or not reason_for_interest:
        return jsonify({'error': 'All fields are required'}), 400

    if profession.lower() == 'student' and (not college or not year_of_passing):
        return jsonify({'error': 'Please provide college and year of passing for students'}), 400

    # Save to attendees_details_collection
    attendee_data = {
        'event_id': event_id,
        'email': current_user,  # Save user's email
        'profession': profession,
        'college': college,
        'year_of_passing': year_of_passing,
        'reason_for_interest': reason_for_interest
    }

    db.attendees_details_collection.insert_one(attendee_data)

    # ✅ Update the event's attendees list for compatibility with check_attendee_details
    events_collection.update_one(
        {"_id": ObjectId(event_id)},
        {"$addToSet": {"attendees": {"email": current_user}}}  # Just store email to mark "filled"
    )

    # Update analysis
    update_attendee_analysis(event_id)

    return jsonify({'message': 'Details saved successfully'}), 201


def update_attendee_analysis(event_id):
    # Aggregate data for analysis from attendees_details collection
    profession_data = db.attendees_details_collection.aggregate([
        {'$match': {'event_id': event_id}},
        {'$group': {'_id': '$profession', 'count': {'$sum': 1}}}
    ])

    interest_data = db.attendees_details.aggregate([
        {'$match': {'event_id': event_id}},
        {'$group': {'_id': '$reason_for_interest', 'count': {'$sum': 1}}}
    ])

    # Prepare aggregated analysis data
    profession_analysis = {item['_id']: item['count'] for item in profession_data}
    interest_analysis = {item['_id']: item['count'] for item in interest_data}

    # Check if event already has analysis data, if not, create it
    analysis_data = db.attendee_analysis.find_one({'event_id': event_id})

    if analysis_data:
        # Update the existing analysis data
        db.attendee_analysis.update_one(
            {'event_id': event_id},
            {'$set': {
                'profession_analysis': profession_analysis,
                'interest_analysis': interest_analysis
            }}
        )
    else:
        # Create new analysis data for the event
        db.attendee_analysis.insert_one({
            'event_id': event_id,
            'profession_analysis': profession_analysis,
            'interest_analysis': interest_analysis
        })
#--------------------------------
@app.route('/api/events/<event_id>/attendee-analysis', methods=['GET'])
def analyze_attendees(event_id):
    # Retrieve the analysis data from the attendee_analysis collection
    analysis_data = db.attendee_analysis.find_one({'event_id': event_id})

    if not analysis_data:
        return jsonify({'error': 'No analysis data found for this event'}), 404

    # Return the analysis data for profession and interest distribution
    return jsonify({
        'profession_analysis': analysis_data.get('profession_analysis', {}),
        'interest_analysis': analysis_data.get('interest_analysis', {})
    })
#----------------------------------------
@app.route('/api/events/<event_id>/attendees/check', methods=['GET'])
@jwt_required()
def check_attendee_details(event_id):
    current_user = get_jwt_identity()
    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if not event:
        return jsonify({"error": "Event not found"}), 404

    attendee = next((a for a in event.get("attendees", []) if a.get("email") == current_user), None)
    if attendee:
        return jsonify({"filled": True})
    return jsonify({"filled": False})
#-------------------------------------------
@app.route("/api/events/<event_id>/attendees/details", methods=["GET"])
@jwt_required()
def get_event_attendees_details(event_id):
    try:
        # Fetch all attendee descriptive details for this event
        details = list(db.attendees_details_collection.find({"event_id": event_id}))

        # Convert ObjectIds to strings
        for detail in details:
            detail["_id"] = str(detail["_id"])

        return jsonify(details), 200

    except Exception as e:
        print("Error in /api/events/<event_id>/attendees/details:", e)
        return jsonify({"error": "Failed to fetch attendee details"}), 500
# user checking at the venue
@app.route("/api/events/<event_id>/checkin", methods=["POST"])
@jwt_required()
def check_in_attendee(event_id):
    try:
        data = request.json
        qr_code_data = data.get("qr_code")

        if not qr_code_data:
            return jsonify({"error": "QR code data is required"}), 400

        # Parse the QR code data
        qr_parts = qr_code_data.split("|")
        user_id = None
        scanned_event_id = None

        for part in qr_parts:
            if part.startswith("user_id:"):
                user_id = part.split(":")[1]
            elif part.startswith("event_id:"):
                scanned_event_id = part.split(":")[1]

        # Validate the event ID
        if scanned_event_id != event_id:
            return jsonify({"error": "QR code does not match this event"}), 400

        # Check if the attendee is registered for the event
        attendee = attendees_collection.find_one({"event_id": event_id, "user_id": user_id})
        if not attendee:
            return jsonify({"error": "Attendee not registered for this event"}), 404

        # Check if the attendee is already checked in
        if attendee.get("checked_in", False):
            return jsonify({"error": "Attendee already checked in"}), 400

        # Mark the attendee as checked in
        attendees_collection.update_one(
            {"event_id": event_id, "user_id": user_id},
            {"$set": {"checked_in": True}}
        )

        return jsonify({"message": "Attendee checked in successfully"}), 200

    except Exception as e:
        print(f"Error during check-in: {e}")
        return jsonify({"error": "Failed to check in attendee"}), 500
if __name__ == "__main__":
    app.run(debug=True)