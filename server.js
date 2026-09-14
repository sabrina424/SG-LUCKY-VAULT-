const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const db = new Database(process.env.DB_PATH || "./vault.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  number_value TEXT DEFAULT '',
  payment_status TEXT DEFAULT 'Pending',
  access_status TEXT DEFAULT 'Locked',
  notice TEXT DEFAULT '',
  notice_enabled INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
try { db.exec("ALTER TABLE customers ADD COLUMN notice_enabled INTEGER DEFAULT 1"); } catch (e) {}

app.use(express.urlencoded({extended:false}));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:"lax", secure: process.env.NODE_ENV==="production", maxAge: 1000*60*60*8 }
}));
app.use(express.static(path.join(__dirname,"public")));

function clean(s){ return String(s ?? "").trim(); }
function makeRef(){
  return "SV-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}
function requireAdmin(req,res,next){
  if(req.session.admin) return next();
  res.redirect("/admin-login.html");
}
function requireCustomer(req,res,next){
  if(req.session.customerId) return next();
  res.redirect("/");
}

app.post("/api/customer/login", (req,res)=>{
  const ref=clean(req.body.ref), password=clean(req.body.password);
  const c=db.prepare("SELECT * FROM customers WHERE ref=? AND active=1").get(ref);
  if(!c || !bcrypt.compareSync(password,c.password_hash)){
    return res.status(401).json({ok:false,message:"Wrong password. Please enter the correct password."});
  }
  req.session.customerId=c.id;
  res.json({ok:true});
});

app.get("/api/customer/me", requireCustomer, (req,res)=>{
  const c=db.prepare("SELECT id,ref,payment_status,access_status,notice,notice_enabled,number_value FROM customers WHERE id=? AND active=1").get(req.session.customerId);
  if(!c) return res.status(401).json({ok:false});
  const allowed = c.access_status === "Unlocked";
  res.json({ok:true, customer:{...c, number_value: allowed ? c.number_value : null}});
});

app.post("/api/customer/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.post("/api/admin/login",(req,res)=>{
  if(clean(req.body.password) !== ADMIN_PASSWORD)
    return res.status(401).json({ok:false,message:"Wrong admin password."});
  req.session.admin=true; res.json({ok:true});
});
app.post("/api/admin/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/admin/customers", requireAdmin,(req,res)=>{
  res.json(db.prepare("SELECT id,ref,payment_status,access_status,active,created_at FROM customers ORDER BY id DESC").all());
});

app.post("/api/admin/customers", requireAdmin,(req,res)=>{
  const password=clean(req.body.password);
  if(password.length < 6) return res.status(400).json({ok:false,message:"Customer password must be at least 6 characters."});
  let ref=clean(req.body.ref).toUpperCase() || makeRef();
  const hash=bcrypt.hashSync(password,12);
  try{
    const info=db.prepare("INSERT INTO customers(ref,password_hash,number_value,payment_status,access_status,notice,notice_enabled) VALUES(?,?,?,?,?,?,?)")
      .run(ref,hash,clean(req.body.number_value),"Pending","Locked",clean(req.body.notice),1);
    res.json({ok:true,id:info.lastInsertRowid,ref});
  }catch(e){res.status(400).json({ok:false,message:"Reference already exists or data is invalid."});}
});

app.put("/api/admin/customers/:id", requireAdmin,(req,res)=>{
  const id=Number(req.params.id);
  const c=db.prepare("SELECT * FROM customers WHERE id=?").get(id);
  if(!c) return res.status(404).json({ok:false,message:"Customer not found."});
  const number_value=clean(req.body.number_value);
  const payment_status=["Pending","Confirmed"].includes(req.body.payment_status)?req.body.payment_status:c.payment_status;
  const access_status=["Locked","Unlocked"].includes(req.body.access_status)?req.body.access_status:c.access_status;
  const notice=clean(req.body.notice);
  const notice_enabled = req.body.notice_enabled === undefined ? c.notice_enabled : (String(req.body.notice_enabled) === "1" ? 1 : 0);
  db.prepare("UPDATE customers SET number_value=?,payment_status=?,access_status=?,notice=?,notice_enabled=? WHERE id=?")
    .run(number_value,payment_status,access_status,notice,notice_enabled,id);
  res.json({ok:true});
});

app.delete("/api/admin/customers/:id", requireAdmin,(req,res)=>{
  db.prepare("UPDATE customers SET active=0 WHERE id=?").run(Number(req.params.id));
  res.json({ok:true});
});

app.get("/api/admin/status",requireAdmin,(req,res)=>res.json({ok:true}));

app.listen(PORT,()=>console.log(`SG Lucky VAULT running on port ${PORT}`));