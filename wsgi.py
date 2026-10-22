
from app import app, init_db

# Register the SEO routes for Google Search.
import seo_routes

# Create or update database tables before the website starts.
with app.app_context():
    init_db()
