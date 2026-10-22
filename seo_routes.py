
from flask import Response
from app import app


# Tell search engines where the sitemap is and which pages they can crawl.
@app.route("/robots.txt")
def robots_txt():
    content = """User-agent: *
Allow: /
Disallow: /login
Disallow: /register
Disallow: /logout

Sitemap: https://medicare-plus-yc5d.onrender.com/sitemap.xml
"""
    return Response(content, mimetype="text/plain")


# List the public homepage for Google to discover.
@app.route("/sitemap.xml")
def sitemap_xml():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://medicare-plus-yc5d.onrender.com/</loc>
    </url>
</urlset>
"""
    return Response(content, mimetype="application/xml")
