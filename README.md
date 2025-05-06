# Event Management Backend

This is the backend for the Event Management system, built using Flask. It provides APIs for user authentication, event management, attendee registration, QR code generation, and analytics.

---

## Features

- User authentication (registration, login)
- Role-based access control (Admin, Organizer, User)
- Event creation, modification, and deletion
- Attendee registration with QR code generation
- Email notifications using EmailJS
- Attendee check-in via QR code scanning
- Event analytics and attendee details export

---

## Tech Stack

- **Backend Framework**: Flask
- **Database**: MongoDB
- **Authentication**: JWT (JSON Web Tokens)
- **QR Code Generation**: Python `qrcode` library
- **Email Service**: EmailJS
- **Environment Variables**: Python `dotenv`

---

## API Endpoints

### **Authentication**
- `POST /api/register`: Register a new user.
- `POST /api/login`: Log in a user.
- `GET /api/user`: Fetch logged-in user details.

### **User Management**
- `GET /api/users`: Fetch all users (Admin only).
- `DELETE /api/users/<user_id>`: Delete a user (Admin only).

### **Event Management**
- `POST /api/events`: Create a new event (Organizer only).
- `PUT /api/events/<event_id>`: Update an event (Organizer only).
- `DELETE /api/events/<event_id>`: Delete an event (Organizer only).
- `GET /api/events`: Fetch all events.
- `GET /api/events/<event_id>`: Fetch event details by ID.

### **Attendee Management**
- `POST /api/events/<event_id>/register`: Register a user for an event.
- `GET /api/events/<event_id>/attendees`: Fetch attendees for an event (Organizer only).
- `GET /api/events/<event_id>/attendees/export`: Export attendees as a CSV file (Organizer only).
- `POST /api/events/<event_id>/checkin`: Check in an attendee via QR code.

### **Analytics**
- `GET /api/events/<event_id>/attendee-analysis`: Fetch event analytics (Organizer only).
- `POST /api/events/<event_id>/attendee-details`: Store attendee details for analysis.
- `GET /api/events/<event_id>/attendees/details`: Fetch detailed attendee information.

---

## QR Code Integration

- QR codes are generated during attendee registration and contain the `user_id` and `event_id`.
- The QR code is returned as a Base64-encoded image URL and can be scanned for check-in.

---

## Email Notifications

- Email notifications are sent using **EmailJS**.
- The `send_confirmation_email` function sends event details and the QR code to the attendee's email.

---

## Folder Structure
Backend/ ├── app.py # Main application file 
├── mongo_client.py # MongoDB connection setup
├── requirements.txt # Python dependencies 
├── .env # Environment variables
├── pycache/ # Python cache files
└── README.md # Project documentation

---

## Dependencies

- Flask
- Flask-CORS
- Flask-Bcrypt
- Flask-JWT-Extended
- PyMongo
- Python-Dotenv
- Requests
- qrcode

---

## Contact

For any questions or feedback, please contact:
- **Name**: Sai Gopal Varma
- **GitHub**: [Saigopalvarma](https://github.com/Saigopalvarma)
