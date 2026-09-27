# OpenClaw Google Calendar

Calendar-only OpenClaw plugin. OAuth uses PKCE. User flow: ask OpenClaw to connect Google Calendar, open the returned Google link, press Allow, then paste the callback URL if needed.

Google still requires a one-time OAuth client registration by the plugin owner. Configure `clientId`, optional `clientSecret`, and a registered `redirectUri`, or use `GOOGLE_CALENDAR_CLIENT_ID`, `GOOGLE_CALENDAR_CLIENT_SECRET`, and `GOOGLE_CALENDAR_REDIRECT_URI`.

Tools include auth, calendar CRUD, event CRUD, recurrence and popup/email reminders. Scope: `https://www.googleapis.com/auth/calendar`.
