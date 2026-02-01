# Mercedes-AMG Vehicle Configurator

## Project Overview
This is a high-performance web application designed for the Mercedes-AMG vehicle customization experience. The platform allows users to select models, colors, and trims with real-time visual updates and dynamic price calculation. The application is built with a Flask backend and is optimized for deployment on Google App Engine (GAE).

## Technical Stack
* **Backend**: Python 3.12 / Flask.
* **Frontend**: JavaScript (ES6+), HTML5, CSS3 with Glassmorphism effects.
* **Infrastructure**: Google App Engine Standard Environment.
* **Asset Management**: Local static asset routing via GAE handlers.

## Key Features
* **Dynamic Configuration Engine**: A 6-step workflow (Model, Trim, Color, Wheels, Interior, Summary) managed by a central data state.
* **Real-time Visualizer**: Immediate UI updates when switching models (GT 63, C 63, SL 63) using optimized local assets.
* **Responsive Image Handling**: CSS `object-fit: contain` implementation to ensure high-resolution vehicle renders scale perfectly within the UI without overflow.
* **Live Price Calculation**: Aggregates base MSRP and optional package pricing instantly.

## Project Structure
```text
├── main.py              # Flask application routes and logic
├── app.yaml             # GAE deployment configuration (Runtime: Python 3.12)
├── requirements.txt     # Python dependencies
├── static/              # Static assets
│   ├── css/style.css    # AMG branding and UI layout
│   ├── gt63_black.png   # Optimized model renders
│   ├── c63_black.png    # Optimized model renders
│   └── sl63_white.png   # Optimized model renders
└── templates/
    └── dashboard.html   # Main configurator engine and mockData logic
