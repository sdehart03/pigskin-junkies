# Pigskin Junkies

Server-rendered Python + SQLite app for the Pigskin Junkies college football pick'em contest.

Run locally:

```bash
cd "/Users/scottdehart/Documents/New project/pigskin-junkies-site"
python3 app.py
```

Open `http://127.0.0.1:8001`

Production-ready deployment files:

- [render.yaml](/Users/scottdehart/Documents/New%20project/pigskin-junkies-site/render.yaml)
- [requirements.txt](/Users/scottdehart/Documents/New%20project/pigskin-junkies-site/requirements.txt)

Suggested host:

- Render web service with custom domain `pigskin-junkies.com`

Recommended production environment variables:

- `PIGSKIN_JUNKIES_SECRET`
- `PIGSKIN_JUNKIES_COOKIE_SECURE=1`
- `PIGSKIN_JUNKIES_DB_PATH`

Demo commissioner accounts:

- `scott@pigskin-junkies.com / pigskin12`
- `alex@pigskin-junkies.com / pigskin34`

Participant accounts:

- `jamie@pigskin-junkies.com / pigskin56`
- `morgan@pigskin-junkies.com / pigskin78`
- `taylor@pigskin-junkies.com / pigskin90`
- `casey@pigskin-junkies.com / pigskin11`

Deployment outline:

1. Push this folder to a GitHub repository.
2. Create a new Render web service from that repository.
3. Let Render use `render.yaml` or configure the same commands manually.
4. Add `pigskin-junkies.com` in the Render service settings.
5. Add the DNS records Render gives you at your domain registrar.
6. After DNS verifies, log in with commissioner credentials and replace the demo data.
