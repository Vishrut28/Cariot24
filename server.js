const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const session = require('express-session');
const { OAuth2Client } = require('google-auth-library');
const { google } = require('googleapis');

const CLIENT_ID = '284150378430-p1c7c213dtj12mnmmmr349i7m0mievlj.apps.googleusercontent.com';
const client = new OAuth2Client(CLIENT_ID);

const app = express();
// const path = require('path');
app.use(express.static(path.join(__dirname)));

const port = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, 'uploads');

// Ensure uploads folder exists
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'changeme_secret',
  resave: false,
  saveUninitialized: true
}));

// SQLite setup
const db = new sqlite3.Database('./database.db', err => {
  if (err) throw err;
});

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS yard_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hub_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    comment_type TEXT DEFAULT 'general',
    comment_text TEXT NOT NULL,
    priority TEXT DEFAULT 'medium',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(hub_id) REFERENCES hubs(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    email            TEXT UNIQUE NOT NULL,
    role             TEXT NOT NULL DEFAULT 'ground',
    hub_location     TEXT,
    vehicle_reg_no   TEXT
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS car_assignments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    reg_no       TEXT NOT NULL UNIQUE,
    hub_location TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT 'unknown',
    assigned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS cleaning_reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    reg_no              TEXT NOT NULL,
    hub_location        TEXT NOT NULL,
    cleaning_date       TEXT NOT NULL,
    exterior_video_path TEXT NOT NULL,
    interior_video_path TEXT NOT NULL,
    submission_date     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audit_status        TEXT    DEFAULT 'pending',
    audit_rating        INTEGER DEFAULT 0,
    audit_notes         TEXT,
    user_email          TEXT NOT NULL,
    reason              TEXT    NOT NULL DEFAULT 'unknown'
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS hubs (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT UNIQUE NOT NULL,
    location TEXT NOT NULL,
    sheet_id TEXT NOT NULL
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS hub_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hub_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    FOREIGN KEY(hub_id) REFERENCES hubs(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS no_video_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hub_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    reported_by INTEGER NOT NULL,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(hub_id) REFERENCES hubs(id),
    FOREIGN KEY(reported_by) REFERENCES users(id)
  )`);
  
  // Default admin
  db.run(`INSERT OR IGNORE INTO users (email,role) VALUES (?,?)`,
    ['aditya.thakur@cariotauto.com', 'admin']);
});

// Function to sync hubs from Google Sheets
async function syncHubsFromGoogleSheets() {
  try {
    if (!fs.existsSync("credentials.json")) {
      console.log("❌ credentials.json not found. Skipping Sheets sync.");
      return; // Exit early if no credentials
    }

    console.log("✅ credentials.json found. Starting Sheets sync...");

    const auth = new google.auth.GoogleAuth({
      keyFile: 'credentials.json',
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });

    const sheets = google.sheets({ version: 'v4', auth });
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
      range: 'Sheet1!A2:E',
    });

    const rows = response.data.values;
    
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        console.log('🔄 Starting complete hub sync with cleanup...');
        
        db.run('BEGIN TRANSACTION');
        
        // Clean up existing hub assignments
        db.run('DELETE FROM hub_assignments WHERE role IN (?, ?, ?)', 
          ['yard_manager', 'auditor', 'ground'], (err) => {
          if (err) {
            console.error('❌ Error cleaning hub assignments:', err);
            db.run('ROLLBACK');
            return reject(err);
          }
          console.log('✅ Cleaned existing hub assignments');
          
          // Clear the hubs table
          db.run('DELETE FROM hubs', (err) => {
            if (err) {
              console.error('❌ Error cleaning hubs:', err);
              db.run('ROLLBACK');
              return reject(err);
            }
            console.log('✅ Cleaned existing hubs');
            
            if (rows && rows.length) {
              let processedCount = 0;
              
              rows.forEach(row => {
                const [name, location, yardManagerEmail, auditorEmail, groundTeamEmail] = row;
                
                if (location && name) {
                  db.run(
                    `INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`,
                    [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'],
                    function (err) {
                      if (err) {
                        console.error(`❌ Hub sync error for ${name}:`, err.message);
                      } else {
                        const hubId = this.lastID;
                        console.log(`✅ Created hub: ${name} (ID: ${hubId})`);

                        // Assign users to the new hub
                        if (yardManagerEmail && yardManagerEmail.trim()) {
                          assignUserToHub(yardManagerEmail.trim(), hubId, 'yard_manager');
                          console.log(`  → Assigned yard manager: ${yardManagerEmail}`);
                        }
                        if (auditorEmail && auditorEmail.trim()) {
                          assignUserToHub(auditorEmail.trim(), hubId, 'auditor');
                          console.log(`  → Assigned auditor: ${auditorEmail}`);
                        }
                        if (groundTeamEmail && groundTeamEmail.trim()) {
                          assignUserToHub(groundTeamEmail.trim(), hubId, 'ground');
                          console.log(`  → Assigned ground worker: ${groundTeamEmail}`);
                        }
                      }

                      processedCount++;
                      if (processedCount === rows.length) {
                        db.run('COMMIT', (err) => {
                          if (err) {
                            console.error('❌ Commit error:', err);
                            reject(err);
                          } else {
                            console.log(`✅ Successfully imported ${rows.length} hubs with clean assignments`);
                            resolve();
                          }
                        });
                      }
                    }
                  );
                } else {
                  processedCount++;
                  if (processedCount === rows.length) {
                    db.run('COMMIT', (err) => {
                      if (err) {
                        console.error('❌ Commit error:', err);
                        reject(err);
                      } else {
                        console.log(`✅ Successfully imported ${rows.length} hubs with clean assignments`);
                        resolve();
                      }
                    });
                  }
                }
              }); // Closed the forEach loop properly here
            } else {
              console.log('✅ No hubs found in sheet, sync completed');
              db.run('COMMIT');
              resolve();
            }
          }); // Closed the DELETE FROM hubs callback
        }); // Closed the DELETE FROM hub_assignments callback
      }); // Closed db.serialize
    }); // Closed Promise
  } catch (err) {
    console.error('❌ Google Sheets sync error:', err.message);
    throw err;
  }
}


// Assign user function (outside any try-catch)
function assignUserToHub(email, hubId, role) {
  if (!email || !hubId) {
    console.log(`Skipping assignment: email=${email}, hubId=${hubId}`);
    return;
  }

  db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error(`Database error: ${err.message}`);
      return;
    }

    if (user) {
      db.run(
        `INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) VALUES (?, ?, ?)`,
        [hubId, user.id, role],
        (err) => {
          if (err) console.error(`Error assigning ${email} to hub:`, err);
        }
      );
    } else {
      // Create user if not exists
      db.run(
        `INSERT INTO users (email, role) VALUES (?, ?)`,
        [email, role],
        function (err) {
          if (err) {
            console.error(`Error creating user ${email}:`, err);
            return;
          }
          const userId = this.lastID;
          db.run(
            `INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) VALUES (?, ?, ?)`,
            [hubId, userId, role],
            (err) => {
              if (err) console.error(`Error assigning new user to hub:`, err);
            }
          );
        }
      );
    }
  });
}


// Manual hub assignment for specific users
async function assignSpecificHubs() {
  try {
    // Get Agra hub
    const agraHub = await new Promise((resolve) => {
      db.get("SELECT id FROM hubs WHERE location LIKE '%Agra%'", (err, row) => {
        if (err) console.error(err);
        resolve(row?.id);
      });
    });
    
    if (agraHub) {
      assignUserToHub('kanu6280@gmail.com', agraHub, 'yard_manager');
      console.log(`✅ Assigned Agra hub to kanu6280@gmail.com`);
    } else {
      console.error('Agra hub not found');
    }

    // Get Ahmedabad hub
    const ahmedabadHub = await new Promise((resolve) => {
      db.get("SELECT id FROM hubs WHERE location LIKE '%Ahmedabad%'", (err, row) => {
        if (err) console.error(err);
        resolve(row?.id);
      });
    });
    
    if (ahmedabadHub) {
      assignUserToHub('business.uut@gmail.com', ahmedabadHub, 'yard_manager');
      console.log(`✅ Assigned Ahmedabad hub to business.uut@gmail.com`);
    } else {
      console.error('Ahmedabad hub not found');
    }
  } catch (err) {
    console.error('Manual assignment error:', err);
  }
}

// Sync hubs on startup
syncHubsFromGoogleSheets()
  .then(assignSpecificHubs)
  .catch(console.error);

// Middleware for role-based authentication
function requireAuth(role) {
  return (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
    if (role && req.session.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// Google OAuth login
app.post('/google-auth', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'No token' });
  try {
    const ticket = await client.verifyIdToken({ idToken: token, audience: CLIENT_ID });
    const { email } = ticket.getPayload();
    
    db.get(`SELECT * FROM users WHERE email=?`, [email], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      
      // If user doesn't exist, create with default 'ground' role
      const role = user ? user.role : 'ground';
      const hub = user ? user.hub_location : null;
      const vehicle = user ? user.vehicle_reg_no : null;
      
      const finish = id => {
        req.session.userId = id;
        req.session.email = email;
        req.session.role = role;
        req.session.hub = hub;
        req.session.vehicle_reg_no = vehicle;
        res.json({ role, hub, vehicle });
      };
      
      if (!user) {
        db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function (err) {
          if (err) return res.status(500).json({ error: err.message });
          finish(this.lastID);
        });
      } else {
        finish(user.id);
      }
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get dashboard statistics for yard manager's assigned hubs
// Corrected yard manager dashboard stats
app.get('/yard-manager-dashboard-stats', requireAuth('yard_manager'), (req, res) => {
  db.serialize(() => {
    let stats = {};
    
    // Total videos uploaded to yard manager's hubs
    db.get(`
        SELECT COUNT(*) as count FROM cleaning_reports cr
        JOIN hubs h ON cr.hub_location = h.name
        JOIN hub_assignments ha ON h.id = ha.hub_id
        WHERE ha.user_id = ? AND ha.role = 'yard_manager'
    `, [req.session.userId], (err, row) => {
        if (err) console.error(err);
        stats.total_videos = row ? row.count : 0;
        
        // Today's uploads
        db.get(`
            SELECT COUNT(*) as count FROM cleaning_reports cr
            JOIN hubs h ON cr.hub_location = h.name
            JOIN hub_assignments ha ON h.id = ha.hub_id
            WHERE ha.user_id = ? AND ha.role = 'yard_manager'
            AND DATE(cr.submission_date) = DATE('now')
        `, [req.session.userId], (err, row) => {
            if (err) console.error(err);
            stats.today_uploads = row ? row.count : 0;
            
            // Pending audits
            db.get(`
                SELECT COUNT(*) as count FROM cleaning_reports cr
                JOIN hubs h ON cr.hub_location = h.name
                JOIN hub_assignments ha ON h.id = ha.hub_id
                WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                AND cr.audit_status = 'pending'
            `, [req.session.userId], (err, row) => {
                if (err) console.error(err);
                stats.pending_audits = row ? row.count : 0;
                
                // Approved videos
                db.get(`
                    SELECT COUNT(*) as count FROM cleaning_reports cr
                    JOIN hubs h ON cr.hub_location = h.name
                    JOIN hub_assignments ha ON h.id = ha.hub_id
                    WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                    AND cr.audit_status = 'approved'
                `, [req.session.userId], (err, row) => {
                    if (err) console.error(err);
                    stats.approved_videos = row ? row.count : 0;
                    
                    // Average rating
                    db.get(`
                        SELECT AVG(cr.audit_rating) as avg_rating FROM cleaning_reports cr
                        JOIN hubs h ON cr.hub_location = h.name
                        JOIN hub_assignments ha ON h.id = ha.hub_id
                        WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                        AND cr.audit_rating IS NOT NULL AND cr.audit_rating > 0
                    `, [req.session.userId], (err, row) => {
                        if (err) console.error(err);
                        stats.avg_rating = row && row.avg_rating ? Math.round(row.avg_rating * 10) / 10 : 0;
                        res.json(stats);
                    }); // Fixed this closing
                }); // Fixed this closing
            }); // Fixed this closing
        }); // Fixed this closing
    }); // Fixed this closing
  });
});
// Get all yard managers for admin assignment
app.get('/admin-yard-managers', requireAuth('admin'), (req, res) => {
    db.all(`
        SELECT 
            u.id, u.email, u.role,
            GROUP_CONCAT(h.name || ' (' || h.location || ')') as assigned_hubs
        FROM users u
        LEFT JOIN hub_assignments ha ON u.id = ha.user_id AND ha.role = 'yard_manager'
        LEFT JOIN hubs h ON ha.hub_id = h.id
        WHERE u.role = 'yard_manager'
        GROUP BY u.id, u.email, u.role
        ORDER BY u.email
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// Assign yard manager to hub
app.post('/admin-assign-yard-manager', requireAuth('admin'), (req, res) => {
    const { email, hub_id } = req.body;
    
    if (!email || !hub_id) {
        return res.status(400).json({ error: 'Email and hub_id are required' });
    }
    
    // Create user if doesn't exist
    db.get(`SELECT id FROM users WHERE email = ? AND role = 'yard_manager'`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (!user) {
            db.run(`INSERT INTO users (email, role) VALUES (?, 'yard_manager')`, [email], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                assignToHub(this.lastID, hub_id, res);
            });
        } else {
            assignToHub(user.id, hub_id, res);
        }
    });
    
    function assignToHub(userId, hubId, res) {
        db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) VALUES (?, ?, 'yard_manager')`, 
            [hubId, userId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Yard manager assigned successfully' });
        });
    }
});

// Remove yard manager assignment
app.delete('/admin-remove-yard-manager', requireAuth('admin'), (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    db.get(`SELECT id FROM users WHERE email = ? AND role = 'yard_manager'`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: 'Yard manager not found' });
        
        db.run(`DELETE FROM hub_assignments WHERE user_id = ? AND role = 'yard_manager'`, 
            [user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'All assignments removed' });
        });
    });
});

// Get uploaded videos for yard manager's assigned hubs
app.get('/yard-manager-videos', requireAuth('yard_manager'), (req, res) => {
    db.all(`
        SELECT 
            cr.id, cr.reg_no, cr.hub_location, cr.cleaning_date,
            cr.exterior_video_path, cr.interior_video_path,
            cr.submission_date, cr.user_email as ground_worker,
            cr.audit_status, cr.audit_rating, cr.audit_notes,
            h.name as hub_name, h.location as hub_location_full
        FROM cleaning_reports cr
        JOIN hubs h ON cr.hub_location = h.name
        JOIN hub_assignments ha ON h.id = ha.hub_id
        WHERE ha.user_id = ? AND ha.role = 'yard_manager'
        ORDER BY cr.submission_date DESC
        LIMIT 100
    `, [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// Get assigned car for ground worker
app.get('/car-hub', requireAuth('ground'), (req, res) => {
  const regNo = req.query.reg_no;
  if (!regNo) return res.status(400).json({ error: 'No reg_no provided' });

  db.get(
    `SELECT hub_location FROM car_assignments WHERE reg_no = ?`,
    [regNo],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'Car not assigned to any hub' });
      res.json({ hub_location: row.hub_location });
    }
  );
});

// Session info
app.get('/user-info', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  res.json({
    email: req.session.email,
    role: req.session.role,
    hub: req.session.hub,
    vehicle: req.session.vehicle_reg_no
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('connect.sid').json({}));
});

// Admin Stats
app.get('/admin-stats', requireAuth('admin'), (req, res) => {
  db.serialize(() => {
    let stats = {};
    
    db.get('SELECT COUNT(*) as count FROM car_assignments', (err, row) => {
      stats.total_assigned = err ? 0 : (row.count || 0);
      
      db.get('SELECT COUNT(DISTINCT reg_no) as count FROM cleaning_reports WHERE audit_status = "approved"', (err, row) => {
        stats.total_cleaned = err ? 0 : (row.count || 0);
        
        db.get(`SELECT COUNT(*) as count FROM car_assignments ca
                LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
                WHERE cr.id IS NULL AND julianday('now') - julianday(ca.assigned_at) > 5`, (err, row) => {
          stats.overdue_count = err ? 0 : (row.count || 0);
          res.json(stats);
        });
      });
    });
  });
});

// Pending reports count
app.get('/pending-reports', requireAuth('admin'), (req, res) => {
  db.get('SELECT COUNT(*) as count FROM cleaning_reports WHERE audit_status = "pending"', (err, row) => {
    if (err) {
      console.error('Pending reports error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ count: row.count || 0 });
  });
});

// Submit cleaning report (Ground Team)
app.post('/submit',
  requireAuth('ground'),
  upload.fields([
    { name: 'exterior_video', maxCount: 1 },
    { name: 'interior_video', maxCount: 1 }
  ]),
  (req, res) => {
    const { reg_no, hub_location, cleaning_date } = req.body;

    // 1. Check if car exists for this hub
    db.get(
      `SELECT reason FROM car_assignments WHERE reg_no=? AND hub_location=?`,
      [reg_no, hub_location],
      (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) {
          return res.status(400).json({ 
            error: "This car is not assigned to the selected hub." 
          });
        }

        // 2. Check for existing report
        db.get(
          `SELECT id FROM cleaning_reports 
          WHERE reg_no=? AND hub_location=? AND cleaning_date=?`,
          [reg_no, hub_location, cleaning_date],
          (err, existingReport) => {
            if (err) return res.status(500).json({ error: err.message });
            
            if (existingReport) {
              return res.status(400).json({ 
                error: `Cleaning report for vehicle ${reg_no} on ${cleaning_date} already exists.` 
              });
            }

            // 3. Save new report
            const reason = row.reason || 'unknown';
            
            db.run(
              `INSERT INTO cleaning_reports
              (reg_no, hub_location, cleaning_date,
              exterior_video_path, interior_video_path,
              user_email, reason)
              VALUES (?, ?, ?, ?, ?, ?, ?)`,
              [reg_no, hub_location, cleaning_date,
              req.files.exterior_video[0].path,
              req.files.interior_video[0].path,
              req.session.email, reason],
              function (err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ 
                  id: this.lastID,
                  message: 'Cleaning report submitted successfully!'
                });
              }
            );
          }
        );
      }
    );
  }
);

// Set user role (admin only)
app.post('/set-user-role', requireAuth('admin'), (req, res) => {
  const { email, role } = req.body;
  if (!email || !role) return res.status(400).json({ error: 'Email and role are required.' });

  db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (user) {
      db.run(`UPDATE users SET role = ? WHERE email = ?`, [role, email], err => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `Role for ${email} set to ${role}` });
      });
    } else {
      db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `User ${email} created with role ${role}` });
      });
    }
  });
});

// Sync hubs from Google Sheet
app.post('/sync-hubs', requireAuth('admin'), async (req, res) => {
  try {
    await syncHubsFromGoogleSheets();
    res.json({ success: true, message: 'Sheet synced successfully' });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Sync failed', details: err.message });
  }
});

// List hubs
app.get('/hubs', requireAuth('admin'), (req, res) => {
  db.all('SELECT id, name, location, sheet_id FROM hubs', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Hub adherence reports
app.get('/daily-adherence', requireAuth('admin'), (req, res) => {
  const hub = req.query.hub;
  if (!hub) return res.status(400).json({ error: 'Hub parameter is required' });

  const query = `
      SELECT
          DATE(ca.assigned_at) as date,
          COUNT(DISTINCT ca.reg_no) as assigned,
          COUNT(DISTINCT CASE
              WHEN cr.audit_status = 'approved'
              AND cr.hub_location = ca.hub_location
              THEN cr.reg_no
          END) as cleaned
      FROM car_assignments ca
      LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no 
          AND ca.hub_location = cr.hub_location
      WHERE ca.hub_location = ?
      GROUP BY DATE(ca.assigned_at)
      ORDER BY DATE(ca.assigned_at) DESC
      LIMIT 30
  `;

  db.all(query, [hub], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const result = rows.map(row => ({
      date: row.date,
      assigned: row.assigned || 0,
      cleaned: row.cleaned || 0,
      adherence: row.assigned ? Math.round((row.cleaned / row.assigned) * 100) : 0
    }));

    res.json(result);
  });
});

// List car assignments
app.get('/car-assignments', requireAuth('admin'), (req, res) => {
  db.all(`SELECT reg_no, hub_location, reason, assigned_at FROM car_assignments`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get assigned hubs for yard manager
app.get('/yard-hubs', requireAuth('yard_manager'), (req, res) => {
  db.all(`
    SELECT h.id, h.name, h.location, 
      (SELECT COUNT(*) FROM cleaning_reports 
      WHERE hub_location = h.name AND DATE(submission_date) = DATE('now')) as video_uploaded,
      (SELECT MAX(submission_date) FROM cleaning_reports 
      WHERE hub_location = h.name) as video_date
    FROM hubs h
    JOIN hub_assignments a ON h.id = a.hub_id
    WHERE a.user_id = ? AND a.role = 'yard_manager'
  `, [req.session.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Report no video
app.post('/report-no-video', requireAuth('yard_manager'), (req, res) => {
  const { hub_id, reason } = req.body;
  db.run(
    `INSERT INTO no_video_reports (hub_id, reason, reported_by) 
    VALUES (?, ?, ?)`,
    [hub_id, reason, req.session.userId],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Get assigned hub for ground worker
app.get('/ground-hub', requireAuth('ground'), (req, res) => {
  db.get(`
    SELECT h.name, h.location FROM hubs h
    JOIN hub_assignments a ON h.id = a.hub_id
    WHERE a.user_id = ? AND a.role = 'ground'
    LIMIT 1
  `, [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row || {});
  });
});

// Get pending audits for auditor
app.get('/pending-audits', requireAuth('auditor'), (req, res) => {
  db.all(`
      SELECT r.id, r.reg_no, r.hub_location, r.cleaning_date,
            r.exterior_video_path, r.interior_video_path,
            r.submission_date, r.user_email
      FROM cleaning_reports r
      WHERE r.audit_status = 'pending'
      AND r.id = (
          SELECT MAX(cr.id) 
          FROM cleaning_reports cr 
          WHERE cr.reg_no = r.reg_no 
          AND cr.hub_location = r.hub_location
          AND cr.audit_status = 'pending'
      )
      ORDER BY r.submission_date DESC
  `, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
  });
});

// Submit audit
app.post('/audit/:id', requireAuth('auditor'), (req, res) => {
  const { audit_status, audit_rating, audit_notes } = req.body;
  
  // Validate rating
  if (audit_rating && (audit_rating < 1 || audit_rating > 5)) {
    return res.status(400).json({ error: 'Rating must be between 1 and 5' });
  }
  
  // Validate required fields
  if (!audit_status || !audit_rating) {
    return res.status(400).json({ error: 'Status and rating are required' });
  }

  db.run(
    `UPDATE cleaning_reports
    SET audit_status=?, audit_rating=?, audit_notes=?
    WHERE id=?`,
    [audit_status, audit_rating, audit_notes || '', req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Audit record not found' });
      }
      
      res.json({ 
        success: true, 
        message: 'Audit submitted successfully',
        changes: this.changes 
      });
    }
  );
});

// Serve videos with proper range support
app.get('/video/exterior/:id', (req, res) => {
  db.get(`SELECT exterior_video_path FROM cleaning_reports WHERE id = ?`,
    [req.params.id], (err, row) => {
      if (err || !row) return res.status(404).json({ error: 'Video not found' });

      const videoPath = row.exterior_video_path;
      
      // Check if file exists
      if (!fs.existsSync(videoPath)) {
        return res.status(404).json({ error: 'Video file not found' });
      }

      const stat = fs.statSync(videoPath);
      const fileSize = stat.size;
      const range = req.headers.range;

      // Set Accept-Ranges header
      res.set('Accept-Ranges', 'bytes');

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        
        const file = fs.createReadStream(videoPath, { start, end });
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': 'video/mp4',
        };
        res.writeHead(206, head);
        file.pipe(res);
      } else {
        const head = {
          'Content-Length': fileSize,
          'Content-Type': 'video/mp4',
          'Accept-Ranges': 'bytes'
        };
        res.writeHead(200, head);
        fs.createReadStream(videoPath).pipe(res);
      }
    });
});

// Serve interior video
app.get('/video/interior/:id', (req, res) => {
  db.get(`SELECT interior_video_path FROM cleaning_reports WHERE id = ?`,
    [req.params.id], (err, row) => {
      if (err || !row) return res.status(404).json({ error: 'Video not found' });

      const videoPath = row.interior_video_path;

      if (!fs.existsSync(videoPath)) {
        return res.status(404).json({ error: 'Video file not found' });
      }

      const stat = fs.statSync(videoPath);
      const fileSize = stat.size;
      const range = req.headers.range;

      res.set('Accept-Ranges', 'bytes');

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;

        const file = fs.createReadStream(videoPath, { start, end });
        const head = {
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': 'video/mp4',
        };
        res.writeHead(206, head);
        file.pipe(res);
      } else {
        const head = {
          'Content-Length': fileSize,
          'Content-Type': 'video/mp4',
          'Accept-Ranges': 'bytes'
        };
        res.writeHead(200, head);
        fs.createReadStream(videoPath).pipe(res);
      }
    });
});

// Ground stats route
// Ground stats route - fixed bracket issue
app.get('/ground-stats', requireAuth('ground'), (req, res) => {
  db.serialize(() => {
    let stats = {};

    db.get(`
        SELECT COUNT(*) as count 
        FROM cleaning_reports 
        WHERE user_email = ? AND DATE(submission_date) = DATE('now')
    `, [req.session.email], (err, row) => {
      if (err) console.error(err);
      stats.today_uploads = row ? row.count : 0;

      db.get(`
          SELECT COUNT(*) as count 
          FROM cleaning_reports 
          WHERE user_email = ?
      `, [req.session.email], (err, row) => {
        if (err) console.error(err);
        stats.total_uploads = row ? row.count : 0;
        res.json(stats);
      }); // Added missing parenthesis and semicolon here
    }); // Added missing parenthesis and semicolon here
  });
});

// Health check route
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/debug-index", (req, res) => {
  const indexPath = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(indexPath)) {
    res.send("✅ index.html exists at: " + indexPath);
  } else {
    res.status(404).send("❌ index.html NOT found at: " + indexPath);
  }
});

// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running at http://0.0.0.0:${port}`);

  db.serialize(() => {
    // Optional startup DB logic
  });
});

