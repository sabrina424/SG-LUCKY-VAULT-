# SG Lucky VAULT — Customer Portal

## Recommended hosting
For this server-side project, use **Render Web Service**. The included app uses Express and a local SQLite database for a simple starter deployment. For production with many customers, move the database to PostgreSQL/Supabase.

## Deploy on Render
1. Create a new Web Service and connect this project/repository.
2. Build command: `npm install`
3. Start command: `npm start`
4. Add environment variables:
   - `ADMIN_PASSWORD` = a strong private admin password
   - `SESSION_SECRET` = a long random secret
   - `NODE_ENV` = `production`
5. Deploy.
6. Open `/admin-login.html` to manage customers.

## Important
This is an independent private customer portal. Do not represent it as an official Singapore Pools website or payment system. Only show payment status that is actually verified.


## Notice Board
The admin console now includes a per-customer Notice Board:
- Type any notice/message.
- Turn Notice ON or OFF.
- Save the notice.
- When ON, the message appears on that customer's portal.
- When OFF, the notice is hidden.
