# Mercedes-AMG Vehicle Configurator

## Project Overview
This is a high-performance, interactive web application designed for the Mercedes-AMG vehicle customization experience. Developed as a professional-grade configurator, it allows users to navigate through models, colors, and performance trims with real-time visual updates and dynamic MSRP calculation. The project is built with a Flask backend and is optimized for deployment on Google App Engine (GAE).

## Technical Stack
* **Backend**: Python 3.12 / Flask Framework.
* **Frontend**: JavaScript (ES6+), HTML5, CSS3 with Glassmorphism effects.
* **Cloud Infrastructure**: Google App Engine Standard Environment.
* **Asset Management**: Local static asset routing via GAE handlers, serving high-fidelity model renders.

## Key Features
* **6-Step Progressive Workflow**: Guided configuration through Model, Trim, Color, Wheels, Interior, and Summary stages.
* **Real-time Visualizer**: Immediate UI updates when switching between AMG models (GT 63, C 63, SL 63) using locally hosted assets.
* **Visual Consistency**: Implementation of CSS `object-fit: contain` to ensure vehicle images remain within defined boundaries without distortion or overflow.
* **Live Price Quotation**: Instant aggregation of base MSRP and selected optional package costs.

## Project Structure
```text
├── main.py              # Flask application routing and session logic
├── app.yaml             # GAE deployment manifest (Runtime: Python 3.12)
├── requirements.txt     # Python dependency list
├── README.md            # Project documentation
├── static/              # Static asset directory
│   ├── css/style.css    # AMG branding and UI layout
│   ├── c63_black.png    # AMG C 63 S Performance model render
│   ├── gt63_black.png   # AMG GT 63 S E Performance model render
│   └── sl63_white.png   # AMG SL 63 Roadster model render
└── templates/           # Jinja2 HTML templates
    ├── base.html        # Global layout and navigation
    └── dashboard.html   # Core configurator engine and data state
