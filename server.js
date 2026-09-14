const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const multer=require("multer");
const crypto=require("crypto");
const path=require("path");

const app=express();
const PORT=process.env.PORT||3000;
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"CHANGE_ME";
const SESSION_SECRET=process.env.SESSION_SECRET||"CHANGE_ME_SESSION";

const db=new Database(process.env.DB_PATH||"./vault.db");
db.pragma("journal_mode=WAL");
db.exec(`CREATE TABLE IF NOT EXISTS customers(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ref TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 link_token TEXT NOT NULL UNIQUE,
 image_data TEXT DEFAULT '',
 image_name TEXT DEFAULT '',
 notice TEXT DEFAULT '',
 notice_enabled INTEGER DEFAULT 0,
 active INTEGER DEFAULT 1,
 created_at TEXT NOT NULL
)`);

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{
 httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:28800000
}}));

const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:8*1024*1024},
 fileFilter:(req,file,cb)=>file.mimetype?.startsWith("image/")?cb(null,true):cb(new Error("Only image files are allowed."))
});

function admin(req,res,next){if(req.session.role==="admin")return next();res.status(401).json({error:"Admin login required."});}
function customer(req,res,next){if(req.session.role==="customer"&&req.session.customerId)return next();res.status(401).json({error:"Customer login required."});}

app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/portal.html",(req,res)=>res.sendFile(path.join(__dirname,"public","portal.html")));
app.get("/admin-login.html",(req,res)=>res.sendFile(path.join(__dirname,"public","admin-login.html")));
app.get("/admin.html",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));

app.post("/api/admin/login",(req,res)=>{
 if(req.body.password!==ADMIN_PASSWORD)return res.status(401).json({error:"Invalid admin password."});
 req.session.role="admin";req.session.customerId=null;res.json({ok:true});
});
app.post("/api/admin/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/admin/customers",admin,(req,res)=>{
 res.json(db.prepare(`SELECT id,ref,link_token,notice,notice_enabled,active,image_name,
 CASE WHEN image_data<>'' THEN 1 ELSE 0 END AS has_image,created_at
 FROM customers ORDER BY id DESC`).all());
});

app.post("/api/admin/customers",admin,(req,res)=>{
 const ref=String(req.body.ref||"").trim(), password=String(req.body.password||"");
 const notice=String(req.body.notice||"").trim(), enabled=req.body.notice_enabled?1:0;
 if(!ref||!password)return res.status(400).json({error:"Username and password are required."});
 if(db.prepare("SELECT id FROM customers WHERE ref=?").get(ref))return res.status(409).json({error:"That username already exists."});
 const token=crypto.randomBytes(18).toString("hex");
 const result=db.prepare(`INSERT INTO customers(ref,password_hash,link_token,notice,notice_enabled,active,created_at)
 VALUES(?,?,?,?,?,1,?)`).run(ref,bcrypt.hashSync(password,12),token,notice,enabled,new Date().toISOString());
 res.json({ok:true,customer:{id:result.lastInsertRowid,ref,link_token:token}});
});

app.put("/api/admin/customers/:id",admin,(req,res)=>{
 const id=Number(req.params.id), c=db.prepare("SELECT * FROM customers WHERE id=?").get(id);
 if(!c)return res.status(404).json({error:"Customer not found."});
 const notice=req.body.notice!==undefined?String(req.body.notice):c.notice;
 const enabled=req.body.notice_enabled!==undefined?(req.body.notice_enabled?1:0):c.notice_enabled;
 const active=req.body.active!==undefined?(req.body.active?1:0):c.active;
 if(req.body.password)db.prepare("UPDATE customers SET password_hash=?,notice=?,notice_enabled=?,active=? WHERE id=?")
   .run(bcrypt.hashSync(String(req.body.password),12),notice,enabled,active,id);
 else db.prepare("UPDATE customers SET notice=?,notice_enabled=?,active=? WHERE id=?").run(notice,enabled,active,id);
 res.json({ok:true});
});

app.post("/api/admin/customers/:id/image",admin,upload.single("image"),(req,res)=>{
 if(!req.file)return res.status(400).json({error:"Choose an image first."});
 if(!db.prepare("SELECT id FROM customers WHERE id=?").get(Number(req.params.id)))return res.status(404).json({error:"Customer not found."});
 const data=`data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
 db.prepare("UPDATE customers SET image_data=?,image_name=? WHERE id=?").run(data,req.file.originalname.slice(0,180),Number(req.params.id));
 res.json({ok:true});
});
app.delete("/api/admin/customers/:id/image",admin,(req,res)=>{
 db.prepare("UPDATE customers SET image_data='',image_name='' WHERE id=?").run(Number(req.params.id));res.json({ok:true});
});
app.delete("/api/admin/customers/:id",admin,(req,res)=>{
 db.prepare("DELETE FROM customers WHERE id=?").run(Number(req.params.id));res.json({ok:true});
});

app.post("/api/customer/login",(req,res)=>{
 const ref=String(req.body.ref||"").trim(), password=String(req.body.password||""), token=String(req.body.token||"");
 const c=db.prepare("SELECT * FROM customers WHERE ref=? AND link_token=?").get(ref,token);
 if(!c||!c.active||!bcrypt.compareSync(password,c.password_hash))return res.status(401).json({error:"Invalid username or password."});
 req.session.role="customer";req.session.customerId=c.id;res.json({ok:true});
});
app.get("/api/customer/me",customer,(req,res)=>{
 const c=db.prepare("SELECT * FROM customers WHERE id=?").get(req.session.customerId);
 if(!c||!c.active)return res.status(401).json({error:"Access unavailable."});
 res.json({ref:c.ref,notice:c.notice||"",notice_enabled:!!c.notice_enabled,image_data:c.image_data||"",image_name:c.image_name||""});
});
app.post("/api/customer/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||"Request failed."})});
app.listen(PORT,()=>console.log("SG Lucky VAULT private portal running on port "+PORT));
