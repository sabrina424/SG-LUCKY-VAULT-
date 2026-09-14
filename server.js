const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const db = new Database(
  process.env.DB_PATH || "./vault.db"
);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS customers (

  id INTEGER PRIMARY KEY AUTOINCREMENT,

  ref TEXT UNIQUE NOT NULL,

  password_hash TEXT NOT NULL,

  link_token TEXT UNIQUE NOT NULL,

  image_data TEXT DEFAULT NULL,

  image_name TEXT DEFAULT NULL,

  notice TEXT DEFAULT '',

  notice_enabled INTEGER DEFAULT 0,

  active INTEGER DEFAULT 1,

  created_at TEXT NOT NULL

)
`);


app.use(
  express.json({
    limit: "12mb"
  })
);


app.use(
  express.urlencoded({
    extended: true
  })
);


app.use(
  session({

    secret:
      process.env.SESSION_SECRET ||
      "change-this-secret",

    resave: false,

    saveUninitialized: false,

    cookie: {

      httpOnly: true,

      sameSite: "lax",

      secure:
        process.env.NODE_ENV === "production"

    }

  })
);


const upload =
  multer({

    storage:
      multer.memoryStorage(),

    limits: {

      fileSize:
        8 * 1024 * 1024

    },

    fileFilter:
      (req, file, callback) => {

        if (
          !file.mimetype ||
          !file.mimetype.startsWith("image/")
        ) {

          return callback(
            new Error(
              "Only image files are allowed."
            )
          );

        }

        callback(null, true);

      }

  });


function adminOnly(
  req,
  res,
  next
) {

  if (!req.session.admin) {

    return res
      .status(401)
      .json({
        error:
          "Admin login required."
      });

  }

  next();

}


function customerOnly(
  req,
  res,
  next
) {

  if (!req.session.customerId) {

    return res
      .status(401)
      .json({
        error:
          "Customer login required."
      });

  }

  next();

}


/* =========================
   ADMIN LOGIN
========================= */

app.post(
  "/api/admin/login",
  (req, res) => {

    const password =
      String(
        req.body.password || ""
      );


    if (
      !process.env.ADMIN_PASSWORD ||
      password !==
        process.env.ADMIN_PASSWORD
    ) {

      return res
        .status(401)
        .json({
          error:
            "Invalid admin password."
        });

    }


    req.session.admin = true;

    req.session.customerId = null;


    res.json({
      ok: true
    });

  }
);


app.post(
  "/api/admin/logout",
  adminOnly,
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          ok: true
        });

      }
    );

  }
);


app.get(
  "/api/admin/status",
  (req, res) => {

    res.json({

      loggedIn:
        !!req.session.admin

    });

  }
);


/* =========================
   CUSTOMER LIST
========================= */

app.get(
  "/api/admin/customers",
  adminOnly,
  (req, res) => {

    const rows =
      db.prepare(`

        SELECT

          id,
          ref,
          link_token,
          image_name,
          notice,
          notice_enabled,
          active,
          created_at

        FROM customers

        ORDER BY id DESC

      `).all();


    const customers =
      rows.map(customer => ({

        id:
          customer.id,

        ref:
          customer.ref,

        image_name:
          customer.image_name,

        notice:
          customer.notice,

        notice_enabled:
          !!customer.notice_enabled,

        active:
          !!customer.active,

        created_at:
          customer.created_at,

        link:
          `${req.protocol}://${req.get(
            "host"
          )}/?token=${encodeURIComponent(
            customer.link_token
          )}`

      }));


    res.json(customers);

  }
);


/* =========================
   CREATE CUSTOMER
========================= */

app.post(
  "/api/admin/customers",
  adminOnly,
  async (req, res) => {

    const ref =
      String(
        req.body.ref || ""
      ).trim();


    const password =
      String(
        req.body.password || ""
      );


    const notice =
      String(
        req.body.notice || ""
      );


    const noticeEnabled =
      !!req.body.notice_enabled;


    if (
      !ref ||
      !password
    ) {

      return res
        .status(400)
        .json({

          error:
            "Username and password are required."

        });

    }


    if (
      !/^[A-Za-z0-9._-]{3,40}$/.test(ref)
    ) {

      return res
        .status(400)
        .json({

          error:
            "Username must be 3–40 characters."

        });

    }


    try {

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const token =
        crypto.randomBytes(24)
          .toString("hex");


      const result =
        db.prepare(`

          INSERT INTO customers (

            ref,

            password_hash,

            link_token,

            notice,

            notice_enabled,

            active,

            created_at

          )

          VALUES (?, ?, ?, ?, ?, 1, ?)

        `).run(

          ref,

          passwordHash,

          token,

          notice,

          noticeEnabled ? 1 : 0,

          new Date().toISOString()

        );


      res.json({

        ok: true,

        id:
          result.lastInsertRowid,

        ref:

          ref,

        link:

          `${req.protocol}://${req.get(
            "host"
          )}/?token=${token}`

      });


    } catch (error) {

      if (
        String(error.message)
          .includes("UNIQUE")
      ) {

        return res
          .status(409)
          .json({

            error:
              "That username already exists."

          });

      }


      res
        .status(500)
        .json({

          error:
            "Could not create customer."

        });

    }

  }
);


/* =========================
   UPDATE CUSTOMER
========================= */

app.put(
  "/api/admin/customers/:id",
  adminOnly,
  async (req, res) => {

    const id =
      Number(
        req.params.id
      );


    const customer =
      db.prepare(
        "SELECT * FROM customers WHERE id=?"
      ).get(id);


    if (!customer) {

      return res
        .status(404)
        .json({

          error:
            "Customer not found."

        });

    }


    const notice =
      String(
        req.body.notice ??
        customer.notice
      );


    const noticeEnabled =
      req.body.notice_enabled === undefined
        ? !!customer.notice_enabled
        : !!req.body.notice_enabled;


    const active =
      req.body.active === undefined
        ? !!customer.active
        : !!req.body.active;


    const newPassword =
      String(
        req.body.password || ""
      );


    let passwordHash =
      customer.password_hash;


    if (newPassword) {

      passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

    }


    db.prepare(`

      UPDATE customers

      SET

        password_hash=?,

        notice=?,

        notice_enabled=?,

        active=?

      WHERE id=?

    `).run(

      passwordHash,

      notice,

      noticeEnabled ? 1 : 0,

      active ? 1 : 0,

      id

    );


    res.json({
      ok: true
    });

  }
);


/* =========================
   IMAGE UPLOAD
========================= */

app.post(
  "/api/admin/customers/:id/image",
  adminOnly,
  upload.single("image"),
  (req, res) => {

    if (!req.file) {

      return res
        .status(400)
        .json({

          error:
            "Please choose an image."

        });

    }


    const id =
      Number(
        req.params.id
      );


    const customer =
      db.prepare(
        "SELECT id FROM customers WHERE id=?"
      ).get(id);


    if (!customer) {

      return res
        .status(404)
        .json({

          error:
            "Customer not found."

        });

    }


    const imageData =
      `data:${req.file.mimetype};base64,` +
      req.file.buffer.toString("base64");


    db.prepare(`

      UPDATE customers

      SET

        image_data=?,

        image_name=?

      WHERE id=?

    `).run(

      imageData,

      req.file.originalname,

      id

    );


    res.json({
      ok: true
    });

  }
);


/* =========================
   REMOVE IMAGE
========================= */

app.delete(
  "/api/admin/customers/:id/image",
  adminOnly,
  (req, res) => {

    db.prepare(`

      UPDATE customers

      SET

        image_data=NULL,

        image_name=NULL

      WHERE id=?

    `).run(
      Number(req.params.id)
    );


    res.json({
      ok: true
    });

  }
);


/* =========================
   DELETE CUSTOMER
========================= */

app.delete(
  "/api/admin/customers/:id",
  adminOnly,
  (req, res) => {

    db.prepare(
      "DELETE FROM customers WHERE id=?"
    ).run(
      Number(req.params.id)
    );


    res.json({
      ok: true
    });

  }
);


/* =========================
   CUSTOMER LOGIN
========================= */

app.post(
  "/api/customer/login",
  async (req, res) => {

    const ref =
      String(
        req.body.ref || ""
      ).trim();


    const password =
      String(
        req.body.password || ""
      );


    const token =
      String(
        req.body.token || ""
      ).trim();


    const customer =
      db.prepare(`

        SELECT *

        FROM customers

        WHERE ref=?
        AND link_token=?

      `).get(
        ref,
        token
      );


    if (
      !customer ||
      !customer.active ||
      !(
        await bcrypt.compare(
          password,
          customer.password_hash
        )
      )
    ) {

      return res
        .status(401)
        .json({

          error:
            "Invalid private access details."

        });

    }


    req.session.customerId =
      customer.id;

    req.session.admin =
      false;


    res.json({
      ok: true
    });

  }
);


/* =========================
   CUSTOMER DATA
========================= */

app.get(
  "/api/customer/me",
  customerOnly,
  (req, res) => {

    const customer =
      db.prepare(`

        SELECT

          id,
          ref,
          image_data,
          image_name,
          notice,
          notice_enabled

        FROM customers

        WHERE id=?

      `).get(
        req.session.customerId
      );


    if (!customer) {

      return res
        .status(404)
        .json({

          error:
            "Customer not found."

        });

    }


    res.json({

      ref:
        customer.ref,

      image:
        customer.image_data || null,

      imageName:
        customer.image_name || null,

      notice:
        customer.notice_enabled
          ? customer.notice
          : "",

      noticeEnabled:
        !!customer.notice_enabled

    });

  }
);


/* =========================
   CUSTOMER LOGOUT
========================= */

app.post(
  "/api/customer/logout",
  customerOnly,
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          ok: true
        });

      }
    );

  }
);


/* =========================
   STATIC WEBSITE
========================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);


/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {

    console.error(error);


    res
      .status(400)
      .json({

        error:
          error.message ||
          "Request failed."

      });

  }
);


/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {

    console.log(
      `SG Lucky VAULT running on port ${PORT}`
    );

  }
);
