🛡️ SafeScape — Smart Global Safety Companion 🌍

SafeScape is a next-generation travel safety and emergency response web app built to ensure secure journeys for everyone — especially solo female travelers and explorers in unfamiliar places.
It empowers users to report unsafe incidents, locate emergency services, and trigger SOS alerts instantly, all through an interactive real-time safety map.

🔗 Live App: https://safescape.onrender.com/

👨‍💻 Developed by: Aryan Tripathi

🚀 Key Features
🗺️ Real-Time Safety Map

Interactive Leaflet.js map powered by OpenStreetMap

Displays community-reported hazards, crime alerts, and unsafe zones

🚨 Emergency SOS System

One-click SOS alert sends live location + distress message

Integrated with Twilio SMS API and SendGrid Email

📍 Community Hazard Reporting

Users can submit real-time safety reports with map pinpoints

Verifiable and location-based tagging for authenticity

🏥 Emergency Services Finder

Instantly locate nearest police stations, hospitals, or safe shelters

Category-based filtering for quick help

🌙 Modern UI & UX

Sleek dark/light theme toggle

Fully responsive and mobile-optimized interface

♿ Accessibility Support

Inclusive design principles for better user safety awareness

🛠️ Technology Stack
Layer	Technology
Frontend	HTML5, CSS3, JavaScript, Leaflet.js
Backend	Flask (Python), Gunicorn
Database	SQLite (Local) / PostgreSQL (Production)
Authentication	JWT Tokens
APIs & Integrations	Twilio, SendGrid, OpenStreetMap
Deployment	Render.com
Version Control	Git + GitHub
⚙️ Local Setup & Installation
🔹 Clone Repository
git clone https://github.com/Aryan1296/SafeScape.git
cd SafeScape

🔹 Install Dependencies
pip install -r requirements.txt

🔹 Run Application Locally
python backend/main.py


Open your browser → http://127.0.0.1:5000

Your local SafeScape instance will start! 🎉

🌐 Deploy on Render

1️⃣ Push your code to GitHub:

git add .
git commit -m "Deploy SafeScape to Render"
git push origin main


2️⃣ Setup Render:

Go to Render.com

Create a New Web Service

Connect your GitHub repository

Start Command:

gunicorn backend.main:app


Add environment variables:

FLASK_ENV=production
PORT=10000


✅ Render automatically builds & deploys your project.
🌐 App will go live at: https://safescape.onrender.com

🔌 API Endpoints Overview
🔐 Authentication
Method	Endpoint	Description
POST	/auth/register	Register a new user
POST	/auth/login	Login existing user
⚠️ Safety Reports
Method	Endpoint	Description
GET	/safety/reports	Get all hazard reports
POST	/safety/reports	Submit a new hazard report
🆘 Emergency
Method	Endpoint	Description
POST	/emergency/sos	Send SOS alert with location
GET	/emergency/contacts	Get emergency contact list
🩺 Health Check
Method	Endpoint	Description
GET	/health	Check API health
GET	/api	API metadata overview
⚙️ Environment Variables
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=your-database-url
FLASK_ENV=production
PORT=10000

🧪 Testing

Test locally before deployment:

python test_app.py --local

💬 Developer Message

“Safety should never be an afterthought.
With SafeScape, my goal is to make global travel and urban movement safer for everyone —
blending technology with humanity.”

— Aryan Tripathi
🎓 B.Tech CSE | 🌐 Web & Cybersecurity Enthusiast
📩 Open to collaborations, contributions, and new ideas!

🤝 Open for Contributions

This is an open-source project, and anyone can contribute!
Whether you’re a developer, designer, or tester — your input is welcome.

Steps to Contribute

Fork this repo

Create your feature branch (git checkout -b feature-name)

Commit changes (git commit -m "Added a new feature")

Push to branch (git push origin feature-name)

Submit a Pull Request 🚀

🌟 Acknowledgments

🌍 OpenStreetMap — for community-driven mapping

🗺️ Leaflet.js — powering interactive map rendering

⚙️ Flask Community — robust and lightweight backend framework

❤️ Contributors — for making the world a safer place through tech

📄 License

This project is licensed under the MIT License.
See the LICENSE
 file for details.

💫 Built with ❤️ by Aryan Tripathi

“Empowering safety through smart, open-source innovation.”

🔗 Live App: https://safescape.onrender.com/
