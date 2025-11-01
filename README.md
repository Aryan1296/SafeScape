# 🛡️ SafeScape - Enhanced Travel Safety Companion

SafeScape is a comprehensive travel safety application designed to help travelers, especially solo female travelers, navigate safely through various locations with real-time hazard reporting, emergency services, and community-driven safety features.

## ✨ Features

- **🗺️ Interactive Safety Map** - Real-time hazard visualization and safe route planning
- **🚨 Emergency SOS System** - One-click emergency alerts with location sharing
- **📍 Community Reporting** - Report and verify safety hazards in real-time
- **🏥 Emergency Services Locator** - Find nearby police, hospitals, and support services
- **♿ Accessibility Support** - Inclusive design for travelers with disabilities
- **🌙 Dark/Light Mode** - Comfortable viewing in any lighting condition
- **📱 Mobile Responsive** - Works seamlessly on all devices

## 🚀 Quick Start

### Local Development

1. **Clone and Setup**
   ```bash
   cd SAFESCAPE
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python main.py
   ```

3. **Test the Application**
   ```bash
   python test_app.py --local
   ```

4. **Open in Browser**
   - Navigate to `http://localhost:5000`
   - The application should load with the interactive map

### 🌐 Deploy to Render.com

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial SafeScape deployment"
   git push origin main
   ```

2. **Deploy on Render**
   - Go to [render.com](https://render.com)
   - Connect your GitHub repository
   - Render will automatically detect the `render.yaml` configuration
   - Click "Deploy" - the app will be live in minutes!

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite/PostgreSQL
- **Frontend**: HTML5, CSS3, JavaScript
- **Maps**: Leaflet.js with OpenStreetMap
- **Authentication**: JWT tokens
- **Deployment**: Render.com with Gunicorn

## 📱 API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login

### Safety Features
- `GET /safety/reports` - Get hazard reports
- `POST /safety/reports` - Submit hazard report
- `GET /safety/score` - Get area safety score
- `GET /safety/emergency-services` - Find emergency services

### Emergency
- `POST /emergency/sos` - Trigger SOS alert
- `GET /emergency/contacts` - Get emergency contacts

### Health Check
- `GET /health` - Application health status
- `GET /api` - API information

## 🔧 Configuration

### Environment Variables
```bash
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=your-database-url
FLASK_ENV=production
PORT=10000
```

### Database Setup
The application automatically creates the required database tables on first run. For production, set `DATABASE_URL` to your PostgreSQL connection string.

## 🧪 Testing

Run the test suite to verify functionality:
```bash
python test_app.py --local
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Contact the development team

## 🌟 Acknowledgments

- OpenStreetMap for map data
- Leaflet.js for mapping functionality
- Flask community for the excellent framework
- All contributors and testers

---

**Made with ❤️ for safer travels worldwide**