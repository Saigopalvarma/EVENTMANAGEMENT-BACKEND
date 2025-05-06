# mongo_client.py
from pymongo import MongoClient
import atexit

client = MongoClient("mongodb+srv://saigopalvarma227:Saigopal2003@cluster0.wugemae.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["mini_project"]

users_collection = db["users"]
events_collection = db["events"]
attendees_collection = db["attendees"]
attendees_details_collection = db["attendees_details"]

# Ensure the connection is closed properly on exit
atexit.register(client.close)
