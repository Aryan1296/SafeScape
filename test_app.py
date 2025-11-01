#!/usr/bin/env python3
"""
Simple test script to verify SAFESCAPE application functionality
"""

import requests
import json
import sys

def test_local_server(base_url="http://localhost:5000"):
    """Test the local SAFESCAPE server"""
    
    print("🧪 Testing SAFESCAPE Application...")
    print(f"📡 Base URL: {base_url}")
    
    try:
        # Test 1: Health Check
        print("\n1️⃣ Testing Health Check...")
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the app is running:")
        print("   python main.py")
        return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False
    
    try:
        # Test 2: API Info
        print("\n2️⃣ Testing API Info...")
        response = requests.get(f"{base_url}/api", timeout=5)
        if response.status_code == 200:
            print("✅ API info endpoint working")
            api_info = response.json()
            print(f"   Version: {api_info.get('version')}")
            print(f"   Status: {api_info.get('status')}")
        else:
            print(f"❌ API info failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ API info error: {e}")
    
    try:
        # Test 3: Frontend
        print("\n3️⃣ Testing Frontend...")
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Frontend is accessible")
            if "SafeScape" in response.text:
                print("✅ Frontend contains expected content")
            else:
                print("⚠️ Frontend loaded but content may be incomplete")
        else:
            print(f"❌ Frontend failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Frontend error: {e}")
    
    print("\n🎉 Basic tests completed!")
    print("\n📋 Next steps:")
    print("   1. Open http://localhost:5000 in your browser")
    print("   2. Test the interactive features")
    print("   3. Deploy to Render.com using the render.yaml configuration")
    
    return True

def test_deployment_readiness():
    """Check if the app is ready for deployment"""
    
    print("\n🚀 Checking Deployment Readiness...")
    
    required_files = [
        "main.py",
        "requirements.txt", 
        "render.yaml",
        "templates/index.html"
    ]
    
    missing_files = []
    for file in required_files:
        try:
            with open(file, 'r') as f:
                pass
            print(f"✅ {file}")
        except FileNotFoundError:
            print(f"❌ {file} - MISSING")
            missing_files.append(file)
    
    if missing_files:
        print(f"\n❌ Missing files: {missing_files}")
        return False
    else:
        print("\n✅ All required files present")
        return True

if __name__ == "__main__":
    print("SAFESCAPE Application Test Suite")
    print("=" * 50)
    
    # Check deployment readiness first
    if not test_deployment_readiness():
        sys.exit(1)
    
    # Test local server if running
    if len(sys.argv) > 1 and sys.argv[1] == "--local":
        test_local_server()
    else:
        print("\n💡 To test local server, run: python test_app.py --local")
        print("💡 Make sure to start the server first: python main.py")