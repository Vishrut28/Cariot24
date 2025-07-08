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
const port = 3000;
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
  // Create users table with roles
  // Add this table creation in your database initialization section
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
  
  // Create car_assignments table with UNIQUE constraint
  db.run(`CREATE TABLE IF NOT EXISTS car_assignments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    reg_no       TEXT NOT NULL UNIQUE,
    hub_location TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT 'unknown',
    assigned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Cleaning reports
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
  
  // Hubs table with Google Sheets ID
  db.run(`CREATE TABLE IF NOT EXISTS hubs (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT UNIQUE NOT NULL,
    location TEXT NOT NULL,
    sheet_id TEXT NOT NULL
  )`);
  
  // Hub assignments (yard manager, auditor, ground)
  db.run(`CREATE TABLE IF NOT EXISTS hub_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hub_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    FOREIGN KEY(hub_id) REFERENCES hubs(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  
  // No video reports
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
// Replace your existing syncHubsFromGoogleSheets function with this:
// Load yard manager assignments - FIXED VERSION


async function syncHubsFromGoogleSheets() {
  try {
    if (!fs.existsSync('credentials.json')) {
      console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
      return;
    }
    
    const auth = new google.auth.GoogleAuth({
      keyFile: 'credentials.json',
      scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
    });

    const sheets = google.sheets({ version: 'v4', auth });
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
      range: 'Sheet1!A2:E',
    });

    const rows = response.data.values;
    
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        // **Clear the hubs table before importing**
        db.run('DELETE FROM hubs');
        
        if (rows && rows.length) {
          db.run('BEGIN TRANSACTION');
          
          rows.forEach(row => {
            const [name, location, yardManagerEmail, auditorEmail, groundTeamEmail] = row;
            
            if (location) {
              db.run(`INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`, 
                [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'], function(err) {
                if (err) {
                  console.error(`Hub sync error: ${err.message}`);
                  return;
                }
                
                const hubId = this.lastID;
                assignUserToHub(yardManagerEmail, hubId, 'yard_manager');
                assignUserToHub(auditorEmail, hubId, 'auditor');
                assignUserToHub(groundTeamEmail, hubId, 'ground');
              });
            }
          });
          
          db.run('COMMIT', (err) => {
            if (err) {
              console.error('Commit error:', err);
              reject(err);
            } else {
              console.log(`✅ Imported ${rows.length} hubs successfully`);
              resolve();
            }
          });
        } else {
          console.log('✅ No hubs found in sheet');
          resolve();
        }
      });
    });
  } catch (err) {
    console.error('❌ Google Sheets sync error:', err.message);
    throw err;
  }
}


// Function to sync car assignments from Google Sheets
// Function to sync car assignments from Google Sheets
// FIXED: Complete Google Sheets sync function with proper cleanup
async function syncHubsFromGoogleSheets() {
  try {
    if (!fs.existsSync('credentials.json')) {
      console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
      return;
    }
    
    const auth = new google.auth.GoogleAuth({
      keyFile: 'credentials.json',
      scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
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
        
        // *** CRITICAL FIX: Clean up ALL existing hub assignments first ***
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
                  db.run(`INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`, 
                    [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'], function(err) {
                    if (err) {
                      console.error(`❌ Hub sync error for ${name}:`, err.message);
                    } else {
                      const hubId = this.lastID;
                      console.log(`✅ Created hub: ${name} (ID: ${hubId})`);
                      
                      // Assign users to the new hub (only if email provided)
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
                  });
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
              });
            } else {
              console.log('✅ No hubs found in sheet, sync completed');
              db.run('COMMIT');
              resolve();
            }
          });
        });
      });
    });
  } catch (err) {
    console.error('❌ Google Sheets sync error:', err.message);
    throw err;
  }
}




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
      db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
              VALUES (?, ?, ?)`, [hubId, user.id, role], (err) => {
        if (err) console.error(`Error assigning ${email} to hub:`, err);
      });
    } else {
      // Create user if not exists
      db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function(err) {
        if (err) {
          console.error(`Error creating user ${email}:`, err);
          return;
        }
        const userId = this.lastID;
        db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
                VALUES (?, ?, ?)`, [hubId, userId, role], (err) => {
          if (err) console.error(`Error assigning new user to hub:`, err);
        });
      });
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
// Get daily adherence for a hub (or all hubs)
// Fixed adherence report endpoint

// ===== MISSING ENDPOINT - ADD THIS =====

// Get all yard managers for admin assignment - FIXED VERSION
// Get all yard managers for admin assignment - FIXED VERSION
// app.get('/admin-yard-managers', requireAuth('admin'), (req, res) => {
//     const query = `
//         SELECT 
//             u.id, 
//             u.email, 
//             u.role,
//             GROUP_CONCAT(h.name || ' (' || h.location || ')') as assigned_hubs,
//             COUNT(h.id) as hub_count
//         FROM users u
//         LEFT JOIN hub_assignments ha ON u.id = ha.user_id AND ha.role = 'yard_manager'
//         LEFT JOIN hubs h ON ha.hub_id = h.id
//         WHERE u.role = 'yard_manager'
//         GROUP BY u.id, u.email, u.role
//         ORDER BY u.email
//     `;
    
//     db.all(query, [], (err, rows) => {
//         if (err) {
//             console.error('Error fetching yard managers:', err);
//             return res.status(500).json({ error: err.message });
//         }
        
//         // Clean up the data to ensure only hub names appear
//         const cleanedRows = rows.map(row => ({
//             id: row.id,
//             email: row.email,
//             role: row.role,
//             assigned_hubs: row.assigned_hubs || null,
//             hub_count: row.hub_count || 0
//         }));
        
//         res.json(cleanedRows);
//     });
// });
// ===== MISSING ENDPOINTS - ADD THESE TO YOUR SERVER.JS =====

// Get dashboard statistics for yard manager's assigned hubs
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
            stats.total_videos = err ? 0 : (row.count || 0);
            
            // Today's uploads
            db.get(`
                SELECT COUNT(*) as count FROM cleaning_reports cr
                JOIN hubs h ON cr.hub_location = h.name
                JOIN hub_assignments ha ON h.id = ha.hub_id
                WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                AND DATE(cr.submission_date) = DATE('now')
            `, [req.session.userId], (err, row) => {
                stats.today_uploads = err ? 0 : (row.count || 0);
                
                // Pending audits
                db.get(`
                    SELECT COUNT(*) as count FROM cleaning_reports cr
                    JOIN hubs h ON cr.hub_location = h.name
                    JOIN hub_assignments ha ON h.id = ha.hub_id
                    WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                    AND cr.audit_status = 'pending'
                `, [req.session.userId], (err, row) => {
                    stats.pending_audits = err ? 0 : (row.count || 0);
                    
                    // Approved videos
                    db.get(`
                        SELECT COUNT(*) as count FROM cleaning_reports cr
                        JOIN hubs h ON cr.hub_location = h.name
                        JOIN hub_assignments ha ON h.id = ha.hub_id
                        WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                        AND cr.audit_status = 'approved'
                    `, [req.session.userId], (err, row) => {
                        stats.approved_videos = err ? 0 : (row.count || 0);
                        
                        // Average rating
                        db.get(`
                            SELECT AVG(cr.audit_rating) as avg_rating FROM cleaning_reports cr
                            JOIN hubs h ON cr.hub_location = h.name
                            JOIN hub_assignments ha ON h.id = ha.hub_id
                            WHERE ha.user_id = ? AND ha.role = 'yard_manager'
                            AND cr.audit_rating IS NOT NULL AND cr.audit_rating > 0
                        `, [req.session.userId], (err, row) => {
                            stats.avg_rating = err ? 0 : (Math.round((row.avg_rating || 0) * 10) / 10);
                            res.json(stats);
                        });
                    });
                });
            });
        });
    });
});
// ===== ADD THESE ENDPOINTS TO SERVER.JS =====

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

app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));