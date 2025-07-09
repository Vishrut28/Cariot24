// const express = require('express');
// const path = require('path');
// const fs = require('fs');
// const sqlite3 = require('sqlite3').verbose();
// const multer = require('multer');
// const session = require('express-session');
// const { OAuth2Client } = require('google-auth-library');
// const { google } = require('googleapis');

// const CLIENT_ID = '284150378430-p1c7c213dtj12mnmmmr349i7m0mievlj.apps.googleusercontent.com';
// const client = new OAuth2Client(CLIENT_ID);

// const app = express();
// const port = 3000;
// const uploadDir = path.join(__dirname, 'uploads');

// // Ensure uploads folder exists
// if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// // Multer storage config
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, uploadDir),
//   filename: (req, file, cb) => {
//     const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
//     cb(null, file.fieldname + '-' + unique + path.extname(file.originalname));
//   }
// });
// const upload = multer({ storage });

// app.use(express.json());
// app.use(express.static(path.join(__dirname, 'public')));
// app.use(session({
//   secret: 'changeme_secret',
//   resave: false,
//   saveUninitialized: true
// }));

// // SQLite setup
// const db = new sqlite3.Database('./database.db', err => {
//   if (err) throw err;
// });

// // Initialize database
// db.serialize(() => {
//   // Create users table with roles
//   // Add this table creation in your database initialization section
// db.run(`CREATE TABLE IF NOT EXISTS yard_comments (
//   id INTEGER PRIMARY KEY AUTOINCREMENT,
//   hub_id INTEGER NOT NULL,
//   user_id INTEGER NOT NULL,
//   comment_type TEXT DEFAULT 'general',
//   comment_text TEXT NOT NULL,
//   priority TEXT DEFAULT 'medium',
//   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//   FOREIGN KEY(hub_id) REFERENCES hubs(id),
//   FOREIGN KEY(user_id) REFERENCES users(id)
// )`);

//   db.run(`CREATE TABLE IF NOT EXISTS users (
//     id               INTEGER PRIMARY KEY AUTOINCREMENT,
//     email            TEXT UNIQUE NOT NULL,
//     role             TEXT NOT NULL DEFAULT 'ground',
//     hub_location     TEXT,
//     vehicle_reg_no   TEXT
//   )`);
  
//   // Create car_assignments table with UNIQUE constraint
//   db.run(`CREATE TABLE IF NOT EXISTS car_assignments (
//     id           INTEGER PRIMARY KEY AUTOINCREMENT,
//     reg_no       TEXT NOT NULL UNIQUE,
//     hub_location TEXT NOT NULL,
//     reason       TEXT NOT NULL DEFAULT 'unknown',
//     assigned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//   )`);
  
//   // Cleaning reports
//   db.run(`CREATE TABLE IF NOT EXISTS cleaning_reports (
//     id                  INTEGER PRIMARY KEY AUTOINCREMENT,
//     reg_no              TEXT NOT NULL,
//     hub_location        TEXT NOT NULL,
//     cleaning_date       TEXT NOT NULL,
//     exterior_video_path TEXT NOT NULL,
//     interior_video_path TEXT NOT NULL,
//     submission_date     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     audit_status        TEXT    DEFAULT 'pending',
//     audit_rating        INTEGER DEFAULT 0,
//     audit_notes         TEXT,
//     user_email          TEXT NOT NULL,
//     reason              TEXT    NOT NULL DEFAULT 'unknown'
//   )`);
  
//   // Hubs table with Google Sheets ID
//   db.run(`CREATE TABLE IF NOT EXISTS hubs (
//     id    INTEGER PRIMARY KEY AUTOINCREMENT,
//     name  TEXT UNIQUE NOT NULL,
//     location TEXT NOT NULL,
//     sheet_id TEXT NOT NULL
//   )`);
  
//   // Hub assignments (yard manager, auditor, ground)
//   db.run(`CREATE TABLE IF NOT EXISTS hub_assignments (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     hub_id INTEGER NOT NULL,
//     user_id INTEGER NOT NULL,
//     role TEXT NOT NULL,
//     FOREIGN KEY(hub_id) REFERENCES hubs(id),
//     FOREIGN KEY(user_id) REFERENCES users(id)
//   )`);
  
//   // No video reports
//   db.run(`CREATE TABLE IF NOT EXISTS no_video_reports (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     hub_id INTEGER NOT NULL,
//     reason TEXT NOT NULL,
//     reported_by INTEGER NOT NULL,
//     reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     FOREIGN KEY(hub_id) REFERENCES hubs(id),
//     FOREIGN KEY(reported_by) REFERENCES users(id)
//   )`);
  
//   // Default admin
//   db.run(`INSERT OR IGNORE INTO users (email,role) VALUES (?,?)`,
//     ['aditya.thakur@cariotauto.com', 'admin']);
// });

// // Function to sync hubs from Google Sheets
// // Replace your existing syncHubsFromGoogleSheets function with this:
// // Load yard manager assignments - FIXED VERSION




// // Function to sync car assignments from Google Sheets
// // Function to sync car assignments from Google Sheets
// // async function syncCarAssignmentsFromGoogleSheets() {
// //   try {
// //     if (!fs.existsSync('credentials.json')) {
// //       console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
// //       return;
// //     }
// //     const auth = new google.auth.GoogleAuth({
// //       keyFile: 'credentials.json',
// //       scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
// //     });
// //     const sheets = google.sheets({ version: 'v4', auth });
// //     const response = await sheets.spreadsheets.values.get({
// //       spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
// //       range: 'Sheet1!A2:C', // REG_NO, Hub, Reason
// //     });
// //     const rows = response.data.values;
// //     db.serialize(() => {
// //       // **Clear the table before importing**
// //       db.run('DELETE FROM car_assignments');
// //       if (rows && rows.length) {
// //         db.run('BEGIN TRANSACTION');
// //         rows.forEach(row => {
// //           const [reg_no, hub_location, reason] = row;
// //           if (reg_no && hub_location) {
// //             db.run(
// //               `INSERT OR REPLACE INTO car_assignments (reg_no, hub_location, reason) VALUES (?, ?, ?)`,
// //               [reg_no, hub_location, reason || 'unknown'],
// //               (err) => {
// //                 if (err) console.error(`❌ Error assigning ${reg_no}:`, err);
// //               }
// //             );
// //           }
// //         });
// //         db.run('COMMIT');
// //         console.log(`✅ Imported ${rows.length} car assignments successfully`);
// //       }
// //     });
// //     return { success: true, count: rows ? rows.length : 0 };
// //   } catch (err) {
// //     console.error('❌ Car assignment import error:', err.message);
// //     throw err;
// //   }
// // }//this was working....
// // FIXED: Complete Google Sheets sync function with proper cleanup
// async function syncHubsFromGoogleSheets() {
//   try {
//     if (!fs.existsSync('credentials.json')) {
//       console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
//       return;
//     }

//     const auth = new google.auth.GoogleAuth({
//       keyFile: 'credentials.json',
//       scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
//     });

//     const sheets = google.sheets({ version: 'v4', auth });
//     const response = await sheets.spreadsheets.values.get({
//       spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
//       range: 'Sheet1!A2:C', // A: reg_no, B: hub_location, C: reason
//     });

//     const rows = response.data.values;

//     db.serialize(() => {
//       db.run('DELETE FROM hubs');
//       db.run('DELETE FROM car_assignments');
//       if (rows && rows.length) {
//         db.run('BEGIN TRANSACTION');
//         rows.forEach(row => {
//           const [reg_no, hub_location, reason] = row;
//           if (hub_location && hub_location.trim()) {
//             // Insert unique hub names only
//             db.run(
//               `INSERT OR IGNORE INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`,
//               [hub_location, hub_location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM']
//             );
//           }
//           if (reg_no && hub_location) {
//             db.run(
//               `INSERT OR REPLACE INTO car_assignments (reg_no, hub_location, reason) VALUES (?, ?, ?)`,
//               [reg_no, hub_location, reason || 'unknown']
//             );
//           }
//         });
//         db.run('COMMIT');
//         console.log(`✅ Synced ${rows.length} car assignments and hubs from Google Sheets`);
//       }
//     });
//   } catch (err) {
//     console.error('❌ Google Sheets sync error:', err.message);
//     throw err;
//   }
// }



// syncHubsFromGoogleSheets()
//   .then(assignSpecificHubs)
//   .catch(console.error);



// function assignUserToHub(email, hubId, role) {
//   if (!email || !hubId) {
//     console.log(`Skipping assignment: email=${email}, hubId=${hubId}`);
//     return;
//   }
  
//   db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, user) => {
//     if (err) {
//       console.error(`Database error: ${err.message}`);
//       return;
//     }
    
//     if (user) {
//       db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
//               VALUES (?, ?, ?)`, [hubId, user.id, role], (err) => {
//         if (err) console.error(`Error assigning ${email} to hub:`, err);
//       });
//     } else {
//       // Create user if not exists
//       db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function(err) {
//         if (err) {
//           console.error(`Error creating user ${email}:`, err);
//           return;
//         }
//         const userId = this.lastID;
//         db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
//                 VALUES (?, ?, ?)`, [hubId, userId, role], (err) => {
//           if (err) console.error(`Error assigning new user to hub:`, err);
//         });
//       });
//     }
//   });
// }

// // Manual hub assignment for specific users
// async function assignSpecificHubs() {
//   try {
//     // Get Agra hub
//     const agraHub = await new Promise((resolve) => {
//       db.get("SELECT id FROM hubs WHERE location LIKE '%Agra%'", (err, row) => {
//         if (err) console.error(err);
//         resolve(row?.id);
//       });
//     });
    
//     if (agraHub) {
//       assignUserToHub('kanu6280@gmail.com', agraHub, 'yard_manager');
//       console.log(`✅ Assigned Agra hub to kanu6280@gmail.com`);
//     } else {
//       console.error('Agra hub not found');
//     }

//     // Get Ahmedabad hub
//     const ahmedabadHub = await new Promise((resolve) => {
//       db.get("SELECT id FROM hubs WHERE location LIKE '%Ahmedabad%'", (err, row) => {
//         if (err) console.error(err);
//         resolve(row?.id);
//       });
//     });
    
//     if (ahmedabadHub) {
//       assignUserToHub('business.uut@gmail.com', ahmedabadHub, 'yard_manager');
//       console.log(`✅ Assigned Ahmedabad hub to business.uut@gmail.com`);
//     } else {
//       console.error('Ahmedabad hub not found');
//     }
//   } catch (err) {
//     console.error('Manual assignment error:', err);
//   }
// }

// // Sync hubs on startup

// // Middleware for role-based authentication
// function requireAuth(role) {
//   return (req, res, next) => {
//     if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
//     if (role && req.session.role !== role) return res.status(403).json({ error: 'Forbidden' });
//     next();
//   };
// }

// // Google OAuth login
// app.post('/google-auth', async (req, res) => {
//   const { token } = req.body;
//   if (!token) return res.status(400).json({ error: 'No token' });
//   try {
//     const ticket = await client.verifyIdToken({ idToken: token, audience: CLIENT_ID });
//     const { email } = ticket.getPayload();
    
//     db.get(`SELECT * FROM users WHERE email=?`, [email], (err, user) => {
//       if (err) return res.status(500).json({ error: err.message });
      
//       // If user doesn't exist, create with default 'ground' role
//       const role = user ? user.role : 'ground';
//       const hub = user ? user.hub_location : null;
//       const vehicle = user ? user.vehicle_reg_no : null;
      
//       const finish = id => {
//         req.session.userId = id;
//         req.session.email = email;
//         req.session.role = role;
//         req.session.hub = hub;
//         req.session.vehicle_reg_no = vehicle;
//         res.json({ role, hub, vehicle });
//       };
      
//       if (!user) {
//         db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function (err) {
//           if (err) return res.status(500).json({ error: err.message });
//           finish(this.lastID);
//         });
//       } else {
//         finish(user.id);
//       }
//     });
//   } catch {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// });
// // Get daily adherence for a hub (or all hubs)
// // Fixed adherence report endpoint

// // ===== MISSING ENDPOINT - ADD THIS =====

// // Get all yard managers for admin assignment - FIXED VERSION
// // Get all yard managers for admin assignment - FIXED VERSION
// // app.get('/admin-yard-managers', requireAuth('admin'), (req, res) => {
// //     const query = `
// //         SELECT 
// //             u.id, 
// //             u.email, 
// //             u.role,
// //             GROUP_CONCAT(h.name || ' (' || h.location || ')') as assigned_hubs,
// //             COUNT(h.id) as hub_count
// //         FROM users u
// //         LEFT JOIN hub_assignments ha ON u.id = ha.user_id AND ha.role = 'yard_manager'
// //         LEFT JOIN hubs h ON ha.hub_id = h.id
// //         WHERE u.role = 'yard_manager'
// //         GROUP BY u.id, u.email, u.role
// //         ORDER BY u.email
// //     `;
    
// //     db.all(query, [], (err, rows) => {
// //         if (err) {
// //             console.error('Error fetching yard managers:', err);
// //             return res.status(500).json({ error: err.message });
// //         }
        
// //         // Clean up the data to ensure only hub names appear
// //         const cleanedRows = rows.map(row => ({
// //             id: row.id,
// //             email: row.email,
// //             role: row.role,
// //             assigned_hubs: row.assigned_hubs || null,
// //             hub_count: row.hub_count || 0
// //         }));
        
// //         res.json(cleanedRows);
// //     });
// // });
// // ===== MISSING ENDPOINTS - ADD THESE TO YOUR SERVER.JS =====

// // Get all yard managers for admin assignment
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

// // Assign yard manager to hub


// // Remove yard manager assignment


// // Get videos for yard manager's assigned hubs
// app.get('/yard-manager-videos', requireAuth('yard_manager'), (req, res) => {
//     db.all(`
//         SELECT cr.id, cr.reg_no, cr.hub_location, cr.cleaning_date,
//                cr.submission_date, cr.user_email as ground_worker,
//                cr.audit_status, cr.audit_rating, cr.audit_notes
//         FROM cleaning_reports cr
//         JOIN hubs h ON cr.hub_location = h.name
//         JOIN hub_assignments ha ON h.id = ha.hub_id
//         WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//         ORDER BY cr.submission_date DESC
//         LIMIT 100
//     `, [req.session.userId], (err, rows) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(rows || []);
//     });
// });

// // Get audit reports for yard manager's assigned hubs
// app.get('/yard-manager-audits', requireAuth('yard_manager'), (req, res) => {
//     db.all(`
//         SELECT cr.id, cr.reg_no, cr.hub_location, cr.cleaning_date,
//                cr.submission_date, cr.user_email as ground_worker,
//                cr.audit_status, cr.audit_rating, cr.audit_notes
//         FROM cleaning_reports cr
//         JOIN hubs h ON cr.hub_location = h.name
//         JOIN hub_assignments ha ON h.id = ha.hub_id
//         WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//         AND cr.audit_status IN ('approved', 'rejected')
//         ORDER BY cr.submission_date DESC
//     `, [req.session.userId], (err, rows) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(rows || []);
//     });
// });

// // Add this endpoint to verify your database structure
// app.get('/debug-tables', requireAuth('admin'), (req, res) => {
//     db.all(`
//         SELECT name FROM sqlite_master WHERE type='table' 
//         ORDER BY name
//     `, (err, tables) => {
//         if (err) return res.status(500).json({ error: err.message });
        
//         const tableDetails = {};
//         let completed = 0;
        
//         tables.forEach(table => {
//             db.all(`PRAGMA table_info(${table.name})`, (err, columns) => {
//                 if (!err) {
//                     tableDetails[table.name] = columns.map(col => col.name);
//                 }
//                 completed++;
//                 if (completed === tables.length) {
//                     res.json({ tables: tableDetails });
//                 }
//             });
//         });
//     });
// });



// // Get assigned hub for a given car reg number
// app.get('/car-hub', requireAuth('ground'), (req, res) => {
//   const regNo = req.query.reg_no;
//   if (!regNo) return res.status(400).json({ error: 'No reg_no provided' });

//   db.get(
//     `SELECT hub_location FROM car_assignments WHERE reg_no = ?`,
//     [regNo],
//     (err, row) => {
//       if (err) return res.status(500).json({ error: err.message });
//       if (!row) return res.status(404).json({ error: 'Car not assigned to any hub' });
//       res.json({ hub_location: row.hub_location });
//     }
//   );
// });

// // Session info
// app.get('/user-info', (req, res) => {
//   if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
//   res.json({
//     email: req.session.email,
//     role: req.session.role,
//     hub: req.session.hub,
//     vehicle: req.session.vehicle_reg_no
//   });
// });

// // Logout
// app.get('/logout', (req, res) => {
//   req.session.destroy(() => res.clearCookie('connect.sid').json({}));
// });
// app.get('/overdue-cleaning', requireAuth('admin'), (req, res) => {
//   db.get(
//     `SELECT COUNT(*) as count FROM car_assignments ca
//      LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
//      WHERE cr.id IS NULL AND julianday('now') - julianday(ca.assigned_at) > 5`,
//     [],
//     (err, row) => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.json({ count: row.count });
//     }
//   );
// });

// // Get user's assigned cars
// app.get('/my-cars', requireAuth('ground'), (req, res) => {
//   db.all(
//     `SELECT reg_no, reason FROM car_assignments WHERE hub_location = ?`,
//     [req.session.hub],
//     (err, rows) => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.json(rows);
//     }
//   );
// });
// // Admin Stats (NEW ENDPOINT)
// // Admin stats endpoint
// app.get('/admin-stats', requireAuth('admin'), (req, res) => {
//   db.serialize(() => {
//     let stats = {};
    
//     db.get('SELECT COUNT(*) as count FROM car_assignments', (err, row) => {
//       stats.total_assigned = err ? 0 : (row.count || 0);
      
//       db.get('SELECT COUNT(DISTINCT reg_no) as count FROM cleaning_reports WHERE audit_status = "approved"', (err, row) => {
//         stats.total_cleaned = err ? 0 : (row.count || 0);
        
//         db.get(`SELECT COUNT(*) as count FROM car_assignments ca
//                 LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
//                 WHERE cr.id IS NULL AND julianday('now') - julianday(ca.assigned_at) > 5`, (err, row) => {
//           stats.overdue_count = err ? 0 : (row.count || 0);
//           res.json(stats);
//         });
//       });
//     });
//   });
// });

// // Pending reports endpoint
// app.get('/pending-reports', requireAuth('admin'), (req, res) => {
//   db.get('SELECT COUNT(*) as count FROM cleaning_reports WHERE audit_status = "pending"', (err, row) => {
//     if (err) {
//       console.error('Pending reports error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({ count: row.count || 0 });
//   });
// });


// // Pending Reports Count (NEW ENDPOINT)
// app.get('/pending-reports', requireAuth('admin'), (req, res) => {
//   db.get('SELECT COUNT(*) as count FROM cleaning_reports WHERE audit_status = "pending"', (err, row) => {
//     if (err) {
//       console.error('Pending reports error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({ count: row.count || 0 });
//   });
// });
// // COMPREHENSIVE CLEANUP - ADD THIS TO YOUR SERVER.JS
// app.post('/comprehensive-cleanup', requireAuth('admin'), (req, res) => {
//     db.serialize(() => {
//         db.run('BEGIN TRANSACTION');
        
//         db.get(`SELECT COUNT(*) as total_before FROM cleaning_reports`, (err, beforeCount) => {
//             if (err) {
//                 db.run('ROLLBACK');
//                 return res.status(500).json({ error: err.message });
//             }
            
//             // Delete duplicates (keep latest by ID)
//             db.run(`
//                 DELETE FROM cleaning_reports 
//                 WHERE id NOT IN (
//                     SELECT MAX(id) 
//                     FROM cleaning_reports 
//                     GROUP BY reg_no, hub_location, cleaning_date
//                 )
//             `, (err) => {
//                 if (err) {
//                     db.run('ROLLBACK');
//                     return res.status(500).json({ error: err.message });
//                 }
                
//                 db.get(`SELECT COUNT(*) as total_after FROM cleaning_reports`, (err, afterCount) => {
//                     if (err) {
//                         db.run('ROLLBACK');
//                         return res.status(500).json({ error: err.message });
//                     }
                    
//                     db.run(`
//                         CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_cleaning_report 
//                         ON cleaning_reports(reg_no, hub_location, cleaning_date)
//                     `, (err) => {
//                         if (err) {
//                             db.run('ROLLBACK');
//                             return res.status(500).json({ error: err.message });
//                         }
                        
//                         db.run('COMMIT');
                        
//                         const duplicatesRemoved = beforeCount.total_before - afterCount.total_after;
//                         res.json({
//                             success: true,
//                             message: 'Cleanup completed successfully',
//                             records_before: beforeCount.total_before,
//                             records_after: afterCount.total_after,
//                             duplicates_removed: duplicatesRemoved
//                         });
//                     });
//                 });
//             });
//         });
//     });
// });

// // Submit cleaning report (Ground Team)
// // Submit cleaning report (Ground Team) - UPDATED WITH DUPLICATE CHECK
// app.post('/submit',
//     requireAuth('ground'),
//     upload.fields([
//         { name: 'exterior_video', maxCount: 1 },
//         { name: 'interior_video', maxCount: 1 }
//     ]),
//     (req, res) => {
//         const { reg_no, hub_location, cleaning_date } = req.body;

//         // 1. Check if car exists for this hub
//         db.get(
//             `SELECT reason FROM car_assignments WHERE reg_no=? AND hub_location=?`,
//             [reg_no, hub_location],
//             (err, row) => {
//                 if (err) return res.status(500).json({ error: err.message });
//                 if (!row) {
//                     return res.status(400).json({ 
//                         error: "This car is not assigned to the selected hub." 
//                     });
//                 }

//                 // 2. CHECK FOR EXISTING CLEANING REPORT (NEW)
//                 db.get(
//                     `SELECT id FROM cleaning_reports 
//                      WHERE reg_no=? AND hub_location=? AND cleaning_date=?`,
//                     [reg_no, hub_location, cleaning_date],
//                     (err, existingReport) => {
//                         if (err) return res.status(500).json({ error: err.message });
                        
//                         if (existingReport) {
//                             return res.status(400).json({ 
//                                 error: `Cleaning report for vehicle ${reg_no} on ${cleaning_date} already exists. Each car can only have one report per day.` 
//                             });
//                         }

//                         // 3. Proceed with saving the cleaning report
//                         const reason = row.reason || 'unknown';
                        
//                         db.run(
//                             `INSERT INTO cleaning_reports
//                             (reg_no, hub_location, cleaning_date,
//                              exterior_video_path, interior_video_path,
//                              user_email, reason)
//                             VALUES (?, ?, ?, ?, ?, ?, ?)`,
//                             [reg_no, hub_location, cleaning_date,
//                              req.files.exterior_video[0].path,
//                              req.files.interior_video[0].path,
//                              req.session.email, reason],
//                             function (err) {
//                                 if (err) return res.status(500).json({ error: err.message });
//                                 res.json({ 
//                                     id: this.lastID,
//                                     message: 'Cleaning report submitted successfully!'
//                                 });
//                             }
//                         );
//                     }
//                 );
//             }
//         );
//     }
// );


// // --- Admin routes ---
// // Set user role (admin only)
// app.post('/set-user-role', requireAuth('admin'), (req, res) => {
//   const { email, role } = req.body;
//   if (!email || !role) return res.status(400).json({ error: 'Email and role are required.' });

//   db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, user) => {
//     if (err) return res.status(500).json({ error: err.message });
//     if (user) {
//       db.run(`UPDATE users SET role = ? WHERE email = ?`, [role, email], err => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json({ success: true, message: `Role for ${email} set to ${role}` });
//       });
//     } else {
//       db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function (err) {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json({ success: true, message: `User ${email} created with role ${role}` });
//       });
//     }
//   });
// });

// /* ----------------------------------------------------------------
//    Sync hubs from Google-Sheet (called from Admin ► Sync button)
// ------------------------------------------------------------------*/
// app.post('/sync-hubs', requireAuth('admin'), async (req, res) => {
//   try {
//     await syncHubsFromGoogleSheets();
//     res.json({ success: true, message: 'Sheet synced successfully' });
//   } catch (err) {
//     console.error('Sync error:', err);
//     res.status(500).json({ error: 'Sync failed', details: err.message });
//   }
// });




// // Sync car assignments from Google Sheets
// app.post('/sync-car-assignments', requireAuth('admin'), async (req, res) => {
//   try {
//     const result = await syncCarAssignmentsFromGoogleSheets();
//     res.json({ success: true, message: `Imported ${result.count} car assignments` });
//   } catch (err) {
//     res.status(500).json({ error: 'Import failed', details: err.message });
//   }
// });

// // List hubs
// // REPLACE your current /hubs endpoint with this version




// // Hub adherence reports
// // Get daily adherence for a hub - FIXED VERSION
// // FIXED: Single /daily-adherence endpoint
// app.get('/daily-adherence', requireAuth('admin'), (req, res) => {
//     const hub = req.query.hub;
//     if (!hub) {
//         return res.status(400).json({ error: 'Hub parameter is required' });
//     }

//     // FIXED: Count all approved audits for the hub
//     const query = `
//         SELECT
//             DATE(ca.assigned_at) as date,
//             COUNT(DISTINCT ca.reg_no) as assigned,
//             COUNT(DISTINCT CASE
//                 WHEN cr.audit_status = 'approved'
//                 AND cr.hub_location = ca.hub_location
//                 THEN cr.reg_no
//             END) as cleaned
//         FROM car_assignments ca
//         LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no 
//             AND ca.hub_location = cr.hub_location
//         WHERE ca.hub_location = ?
//         GROUP BY DATE(ca.assigned_at)
//         ORDER BY DATE(ca.assigned_at) DESC
//         LIMIT 30
//     `;

//     db.all(query, [hub], (err, rows) => {
//         if (err) {
//             console.error('Adherence query error:', err);
//             return res.status(500).json({ error: err.message });
//         }

//         const result = rows.map(row => ({
//             date: row.date,
//             assigned: row.assigned || 0,
//             cleaned: row.cleaned || 0,
//             adherence: row.assigned ? Math.round((row.cleaned / row.assigned) * 100) : 0
//         }));

//         res.json(result);
//     });
// });




// // List car assignments
// app.get('/car-assignments', requireAuth('admin'), (req, res) => {
//   db.all(`SELECT reg_no, hub_location, reason, assigned_at FROM car_assignments`, [], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows);
//   });
// });

// // Get all audited videos for yard manager's hubs
// app.get('/audited-videos', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT r.id, r.reg_no, r.hub_location, r.cleaning_date,
//            r.exterior_video_path, r.interior_video_path,
//            r.submission_date, r.user_email, r.audit_status, r.audit_rating, r.audit_notes
//     FROM cleaning_reports r
//     JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//     WHERE ha.user_id = ? AND r.audit_status IN ('approved', 'rejected')
//     ORDER BY r.submission_date DESC
//   `, [req.session.userId], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows);
//   });
// });
// // Yard Manager Audit Progress (renamed to avoid conflict)  
// app.get('/yard-audit-progress', requireAuth('yard_manager'), (req, res) => {
//   db.get(`
//     SELECT
//       (SELECT COUNT(*) FROM cleaning_reports r
//        JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//        WHERE ha.user_id = ?) as total,
//       (SELECT COUNT(*) FROM cleaning_reports r
//        JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//        WHERE ha.user_id = ? AND r.audit_status IN ('approved', 'rejected')) as audited
//   `, [req.session.userId, req.session.userId], (err, row) => {
//     if (err) {
//       console.error('Yard audit progress error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({
//       total: row.total || 0,
//       audited: row.audited || 0
//     });
//   });
// });

// // Auditor Audit Progress (fixed)
// app.get('/audit-progress', requireAuth('auditor'), (req, res) => {
//   db.get(`
//     SELECT
//       (SELECT COUNT(*) FROM cleaning_reports WHERE audit_status IN ('approved', 'rejected', 'pending')) as total,
//       (SELECT COUNT(*) FROM cleaning_reports WHERE audit_status IN ('approved', 'rejected')) as audited
//   `, (err, row) => {
//     if (err) {
//       console.error('Audit progress error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({
//       total: row.total || 0,
//       audited: row.audited || 0
//     });
//   });
// });

// // Audit Statistics for individual cards (NEW ENDPOINT)
// app.get('/audit-stats', requireAuth('auditor'), (req, res) => {
//   db.get(`
//     SELECT
//       (SELECT COUNT(*) FROM cleaning_reports) as total,
//       (SELECT COUNT(*) FROM cleaning_reports WHERE audit_status = 'pending') as pending,
//       (SELECT COUNT(*) FROM cleaning_reports WHERE audit_status = 'approved') as approved,
//       (SELECT COUNT(*) FROM cleaning_reports WHERE audit_status = 'rejected') as rejected
//   `, (err, row) => {
//     if (err) {
//       console.error('Audit stats error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({
//       total: row.total || 0,
//       pending: row.pending || 0,
//       approved: row.approved || 0,
//       rejected: row.rejected || 0
//     });
//   });
// });

// app.get('/audit-video-info/:id', requireAuth('auditor'), (req, res) => {
//   db.get(`
//     SELECT id, reg_no, hub_location, cleaning_date, submission_date, 
//            user_email, audit_status, audit_rating, audit_notes,
//            exterior_video_path, interior_video_path
//     FROM cleaning_reports 
//     WHERE id = ?
//   `, [req.params.id], (err, row) => {
//     if (err) {
//       console.error('Video info error:', err);
//       return res.status(500).json({ error: err.message });
//     }
    
//     if (!row) {
//       return res.status(404).json({ error: 'Audit record not found' });
//     }
    
//     // Check if video files exist
//     const exteriorExists = fs.existsSync(row.exterior_video_path);
//     const interiorExists = fs.existsSync(row.interior_video_path);
    
//     res.json({
//       ...row,
//       exterior_video_available: exteriorExists,
//       interior_video_available: interiorExists
//     });
//   });
// });

// // Assign car to hub
// app.post('/assign-car', requireAuth('admin'), (req, res) => {
//   const { reg_no, hub, reason } = req.body;
  
//   // First try to update existing record
//   db.run(
//     `UPDATE car_assignments SET hub_location = ?, reason = ? WHERE reg_no = ?`,
//     [hub, reason, reg_no],
//     function (err) {
//       if (err) return res.status(500).json({ error: err.message });
      
//       if (this.changes > 0) {
//         // Update successful
//         return res.json({ success: true });
//       }
      
//       // If no record was updated, insert new one
//       db.run(
//         `INSERT INTO car_assignments (reg_no, hub_location, reason) 
//          VALUES (?, ?, ?)`,
//         [reg_no, hub, reason],
//         function (err) {
//           if (err) {
//             // Handle unique constraint violation
//             if (err.code === 'SQLITE_CONSTRAINT') {
//               return res.status(400).json({
//                 error: `Vehicle ${reg_no} is already assigned to a hub`
//               });
//             }
//             return res.status(500).json({ error: err.message });
//           }
//           res.json({ success: true, id: this.lastID });
//         }
//       );
//     }
//   );
// });

// // List users
// app.get('/users', requireAuth('admin'), (req, res) => {
//   db.all(`SELECT email, role, hub_location, vehicle_reg_no FROM users`, [], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows);
//   });
// });

// // Assign user to hub & vehicle
// app.post('/assign-user', requireAuth('admin'), (req, res) => {
//   const { email, hub_location, vehicle_reg_no } = req.body;
//   db.run(
//     `UPDATE users SET hub_location=?, vehicle_reg_no=? WHERE email=?`,
//     [hub_location, vehicle_reg_no, email],
//     err => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.json({ success: true });
//     }
//   );
// });

// // --- Yard Manager routes ---

// // Get assigned hubs
// app.get('/yard-hubs', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT h.id, h.name, h.location, 
//       (SELECT COUNT(*) FROM cleaning_reports 
//        WHERE hub_location = h.name AND DATE(submission_date) = DATE('now')) as video_uploaded,
//       (SELECT MAX(submission_date) FROM cleaning_reports 
//        WHERE hub_location = h.name) as video_date
//     FROM hubs h
//     JOIN hub_assignments a ON h.id = a.hub_id
//     WHERE a.user_id = ? AND a.role = 'yard_manager'
//   `, [req.session.userId], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows);
//   });
// });

// // Report no video
// app.post('/report-no-video', requireAuth('yard_manager'), (req, res) => {
//   const { hub_id, reason } = req.body;
//   db.run(
//     `INSERT INTO no_video_reports (hub_id, reason, reported_by) 
//      VALUES (?, ?, ?)`,
//     [hub_id, reason, req.session.userId],
//     (err) => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.json({ success: true });
//     }
//   );
// });

// // --- Ground Team routes ---

// // Get assigned hub
// app.get('/ground-hub', requireAuth('ground'), (req, res) => {
//   db.get(`
//     SELECT h.name, h.location FROM hubs h
//     JOIN hub_assignments a ON h.id = a.hub_id
//     WHERE a.user_id = ? AND a.role = 'ground'
//     LIMIT 1
//   `, [req.session.userId], (err, row) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(row || {});
//   });
// });

// // --- Auditor routes ---

// // Get pending audits
// // Get pending audits - ONLY LATEST PER CAR
// app.get('/pending-audits', requireAuth('auditor'), (req, res) => {
//     db.all(`
//         SELECT r.id, r.reg_no, r.hub_location, r.cleaning_date,
//                r.exterior_video_path, r.interior_video_path,
//                r.submission_date, r.user_email
//         FROM cleaning_reports r
//         WHERE r.audit_status = 'pending'
//         AND r.id = (
//             SELECT MAX(cr.id) 
//             FROM cleaning_reports cr 
//             WHERE cr.reg_no = r.reg_no 
//             AND cr.hub_location = r.hub_location
//             AND cr.audit_status = 'pending'
//         )
//         ORDER BY r.submission_date DESC
//     `, (err, rows) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(rows);
//     });
// });

// // All Audits for the audits table - NO DUPLICATES
// app.get('/all-audits', requireAuth('auditor'), (req, res) => {
//     db.all(`
//         SELECT id, reg_no, hub_location, cleaning_date, submission_date,
//                audit_status as status, audit_rating, audit_notes, user_email
//         FROM cleaning_reports r
//         WHERE r.id = (
//             SELECT MAX(cr.id) 
//             FROM cleaning_reports cr 
//             WHERE cr.reg_no = r.reg_no 
//             AND cr.hub_location = r.hub_location
//         )
//         ORDER BY submission_date DESC
//         LIMIT 100
//     `, (err, rows) => {
//         if (err) {
//             console.error('All audits error:', err);
//             return res.status(500).json({ error: err.message });
//         }

//         const formattedRows = rows.map(row => ({
//             ...row,
//             audit_date: row.submission_date,
//             status: row.status || 'pending'
//         }));

//         res.json(formattedRows);
//     });
// });
// // CLEANUP DUPLICATES - RUN ONCE TO FIX EXISTING DATA
// app.post('/cleanup-duplicates', requireAuth('admin'), (req, res) => {
//     db.serialize(() => {
//         // Create temporary table with unique entries (keeping latest)
//         db.run(`
//             CREATE TEMPORARY TABLE temp_unique_reports AS
//             SELECT * FROM cleaning_reports cr1
//             WHERE cr1.id = (
//                 SELECT MAX(cr2.id)
//                 FROM cleaning_reports cr2
//                 WHERE cr2.reg_no = cr1.reg_no
//                 AND cr2.hub_location = cr1.hub_location
//                 AND cr2.cleaning_date = cr1.cleaning_date
//             )
//         `);

//         // Count before cleanup
//         db.get(`SELECT COUNT(*) as total_before FROM cleaning_reports`, (err, beforeCount) => {
//             if (err) return res.status(500).json({ error: err.message });

//             // Delete all records and insert unique ones back
//             db.run(`DELETE FROM cleaning_reports`);
//             db.run(`INSERT INTO cleaning_reports SELECT * FROM temp_unique_reports`);

//             // Count after cleanup
//             db.get(`SELECT COUNT(*) as total_after FROM cleaning_reports`, (err, afterCount) => {
//                 if (err) return res.status(500).json({ error: err.message });

//                 const duplicatesRemoved = beforeCount.total_before - afterCount.total_after;
//                 db.run(`DROP TABLE temp_unique_reports`);

//                 res.json({
//                     success: true,
//                     message: `Cleanup completed`,
//                     records_before: beforeCount.total_before,
//                     records_after: afterCount.total_after,
//                     duplicates_removed: duplicatesRemoved
//                 });
//             });
//         });
//     });
// });
// // Add unique constraint to prevent duplicates at database level
// app.post('/add-unique-constraint', requireAuth('admin'), (req, res) => {
//     db.run(`
//         CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_cleaning_report 
//         ON cleaning_reports(reg_no, hub_location, cleaning_date)
//     `, (err) => {
//         if (err) {
//             return res.status(500).json({ error: err.message });
//         }
//         res.json({ 
//             success: true, 
//             message: 'Unique constraint added successfully' 
//         });
//     });
// });


// // Submit audit
// app.post('/audit/:id', requireAuth('auditor'), (req, res) => {
//   const { audit_status, audit_rating, audit_notes } = req.body;
  
//   // Validate rating is between 1-5
//   if (audit_rating && (audit_rating < 1 || audit_rating > 5)) {
//     return res.status(400).json({ error: 'Rating must be between 1 and 5' });
//   }
  
//   // Validate required fields
//   if (!audit_status || !audit_rating) {
//     return res.status(400).json({ error: 'Status and rating are required' });
//   }

//   db.run(
//     `UPDATE cleaning_reports
//      SET audit_status=?, audit_rating=?, audit_notes=?
//      WHERE id=?`,
//     [audit_status, audit_rating, audit_notes || '', req.params.id],
//     function(err) {
//       if (err) return res.status(500).json({ error: err.message });
      
//       if (this.changes === 0) {
//         return res.status(404).json({ error: 'Audit record not found' });
//       }
      
//       res.json({ 
//         success: true, 
//         message: 'Audit submitted successfully',
//         changes: this.changes 
//       });
//     }
//   );
// });

// // Serve videos
// app.get('/video/exterior/:id', (req, res) => {
//   db.get(`SELECT exterior_video_path FROM cleaning_reports WHERE id = ?`,
//     [req.params.id], (err, row) => {
//       if (err || !row) {
//         return res.status(404).json({ error: 'Video not found' });
//       }

//       const videoPath = row.exterior_video_path;
//       const stat = fs.statSync(videoPath);
//       const fileSize = stat.size;
//       const range = req.headers.range;

//       if (range) {
//         const parts = range.replace(/bytes=/, "").split("-");
//         const start = parseInt(parts[0], 10);
//         const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
//         const chunksize = (end - start) + 1;
//         const file = fs.createReadStream(videoPath, { start, end });
//         const head = {
//           'Content-Range': `bytes ${start}-${end}/${fileSize}`,
//           'Accept-Ranges': 'bytes',
//           'Content-Length': chunksize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(206, head);
//         file.pipe(res);
//       } else {
//         const head = {
//           'Content-Length': fileSize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(200, head);
//         fs.createReadStream(videoPath).pipe(res);
//       }
//     });
// });

// app.get('/video/interior/:id', (req, res) => {
//   db.get(`SELECT interior_video_path FROM cleaning_reports WHERE id = ?`,
//     [req.params.id], (err, row) => {
//       if (err || !row) {
//         return res.status(404).json({ error: 'Video not found' });
//       }

//       const videoPath = row.interior_video_path;
//       const stat = fs.statSync(videoPath);
//       const fileSize = stat.size;
//       const range = req.headers.range;

//       if (range) {
//         const parts = range.replace(/bytes=/, "").split("-");
//         const start = parseInt(parts[0], 10);
//         const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
//         const chunksize = (end - start) + 1;
//         const file = fs.createReadStream(videoPath, { start, end });
//         const head = {
//           'Content-Range': `bytes ${start}-${end}/${fileSize}`,
//           'Accept-Ranges': 'bytes',
//           'Content-Length': chunksize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(206, head);
//         file.pipe(res);
//       } else {
//         const head = {
//           'Content-Length': fileSize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(200, head);
//         fs.createReadStream(videoPath).pipe(res);
//       }
//     });
// });

// // Serve static files from uploads directory
// app.use('/uploads', express.static(uploadDir));
// // Place this before "app.listen(...)"
// app.get('/hub-locations', (req, res) => {
//   // Fetch unique hub locations from car_assignments table
//   db.all(`SELECT DISTINCT hub_location FROM car_assignments ORDER BY hub_location`, [], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows.map(row => row.hub_location));
//   });
// });
// app.get('/hub-locations', (req, res) => {
//   db.all(`SELECT DISTINCT location FROM hubs ORDER BY location`, [], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows.map(row => row.location));
//   });
// });
// // Public endpoint to get unique hub names (locations) for dropdowns
// app.get('/hub-names', (req, res) => {
//   db.all(
//     `SELECT DISTINCT hub_location FROM car_assignments WHERE hub_location IS NOT NULL AND hub_location != '' ORDER BY hub_location`,
//     [],
//     (err, rows) => {
//       if (err) return res.status(500).json({ error: err.message });
//       res.json(rows.map(row => row.hub_location));
//     }
//   );
// });
// // NEW ENDPOINT: Get all hubs with adherence rates (only show if adherence > 3)
// app.get('/hub-adherence-summary', requireAuth('admin'), (req, res) => {
//   const query = `
//     SELECT
//       ca.hub_location,
//       COUNT(DISTINCT ca.reg_no)        AS total_assigned,
//       COUNT(DISTINCT CASE WHEN cr.audit_status='approved' THEN cr.reg_no END) AS total_cleaned,
//       ROUND(
//         COUNT(DISTINCT CASE WHEN cr.audit_status='approved' THEN cr.reg_no END)
//         *100.0 / COUNT(DISTINCT ca.reg_no),
//       1) AS adherence_rate
//     FROM car_assignments ca
//     LEFT JOIN cleaning_reports cr
//       ON ca.reg_no = cr.reg_no
//       AND ca.hub_location = cr.hub_location
//     WHERE ca.hub_location IS NOT NULL AND ca.hub_location <> ''
//     GROUP BY ca.hub_location
//     ORDER BY adherence_rate DESC
//   `;
//   db.all(query, [], (err, rows) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json(rows.map(r => ({
//       hub_location:   r.hub_location,
//       total_assigned: r.total_assigned,
//       total_cleaned:  r.total_cleaned,
//       adherence_rate: r.adherence_rate
//     })));
//   });
// });


// // Enhanced video serving with better range support and error handling
// app.get('/video/exterior/:id', (req, res) => {
//   db.get(`SELECT exterior_video_path FROM cleaning_reports WHERE id = ?`,
//     [req.params.id], (err, row) => {
//       if (err || !row) {
//         return res.status(404).json({ error: 'Video not found' });
//       }

//       const videoPath = row.exterior_video_path;
      
//       // Check if file exists
//       if (!fs.existsSync(videoPath)) {
//         return res.status(404).json({ error: 'Video file not found' });
//       }

//       const stat = fs.statSync(videoPath);
//       const fileSize = stat.size;
//       const range = req.headers.range;

//       // Set Accept-Ranges header for all requests
//       res.set('Accept-Ranges', 'bytes');

//       if (range) {
//         const parts = range.replace(/bytes=/, "").split("-");
//         const start = parseInt(parts[0], 10);
//         const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
//         const chunksize = (end - start) + 1;
        
//         const file = fs.createReadStream(videoPath, { start, end });
//         const head = {
//           'Content-Range': `bytes ${start}-${end}/${fileSize}`,
//           'Accept-Ranges': 'bytes',
//           'Content-Length': chunksize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(206, head);
//         file.pipe(res);
//       } else {
//         const head = {
//           'Content-Length': fileSize,
//           'Content-Type': 'video/mp4',
//           'Accept-Ranges': 'bytes'
//         };
//         res.writeHead(200, head);
//         fs.createReadStream(videoPath).pipe(res);
//       }
//     });
// });

// app.get('/video/interior/:id', (req, res) => {
//   db.get(`SELECT interior_video_path FROM cleaning_reports WHERE id = ?`,
//     [req.params.id], (err, row) => {
//       if (err || !row) {
//         return res.status(404).json({ error: 'Video not found' });
//       }

//       const videoPath = row.interior_video_path;
      
//       // Check if file exists
//       if (!fs.existsSync(videoPath)) {
//         return res.status(404).json({ error: 'Video file not found' });
//       }

//       const stat = fs.statSync(videoPath);
//       const fileSize = stat.size;
//       const range = req.headers.range;

//       // Set Accept-Ranges header for all requests
//       res.set('Accept-Ranges', 'bytes');

//       if (range) {
//         const parts = range.replace(/bytes=/, "").split("-");
//         const start = parseInt(parts[0], 10);
//         const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
//         const chunksize = (end - start) + 1;
        
//         const file = fs.createReadStream(videoPath, { start, end });
//         const head = {
//           'Content-Range': `bytes ${start}-${end}/${fileSize}`,
//           'Accept-Ranges': 'bytes',
//           'Content-Length': chunksize,
//           'Content-Type': 'video/mp4',
//         };
//         res.writeHead(206, head);
//         file.pipe(res);
//       } else {
//         const head = {
//           'Content-Length': fileSize,
//           'Content-Type': 'video/mp4',
//           'Accept-Ranges': 'bytes'
//         };
//         res.writeHead(200, head);
//         fs.createReadStream(videoPath).pipe(res);
//       }
//     });
// });

// // Yard Manager Statistics
// app.get('/yard-manager-stats', requireAuth('yard_manager'), (req, res) => {
//   db.serialize(() => {
//     let stats = {};
    
//     // Today's uploads for yard manager's hubs
//     db.get(`
//       SELECT COUNT(*) as count FROM cleaning_reports r
//       JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//       WHERE ha.user_id = ? AND DATE(r.submission_date) = DATE('now')
//     `, [req.session.userId], (err, row) => {
//       stats.today_uploads = err ? 0 : (row.count || 0);
      
//       // Pending review count
//       db.get(`
//         SELECT COUNT(*) as count FROM cleaning_reports r
//         JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//         WHERE ha.user_id = ? AND r.audit_status = 'pending'
//       `, [req.session.userId], (err, row) => {
//         stats.pending_review = err ? 0 : (row.count || 0);
        
//         // This week's uploads
//         db.get(`
//           SELECT COUNT(*) as count FROM cleaning_reports r
//           JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//           WHERE ha.user_id = ? AND DATE(r.submission_date) >= DATE('now', '-7 days')
//         `, [req.session.userId], (err, row) => {
//           stats.week_uploads = err ? 0 : (row.count || 0);
          
//           // Overdue count (cars assigned >5 days ago without cleaning reports)
//           db.get(`
//             SELECT COUNT(*) as count FROM car_assignments ca
//             LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
//             WHERE cr.id IS NULL AND julianday('now') - julianday(ca.assigned_at) > 5
//           `, (err, row) => {
//             stats.overdue_count = err ? 0 : (row.count || 0);
//             res.json(stats);
//           });
//         });
//       });
//     });
//   });
// });

// // Recent uploads for yard manager
// app.get('/yard-recent-uploads', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT r.id, r.reg_no, r.hub_location, r.user_email, r.submission_date, r.audit_status
//     FROM cleaning_reports r
//     JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//     WHERE ha.user_id = ?
//     ORDER BY r.submission_date DESC
//     LIMIT 20
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Error loading recent uploads:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json(rows || []);
//   });
// });

// // Ground worker activity for yard manager
// app.get('/ground-worker-activity', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT 
//       u.email,
//       ha.hub_id,
//       h.name as hub_location,
//       COUNT(CASE WHEN DATE(cr.submission_date) = DATE('now') THEN 1 END) as today_uploads,
//       COUNT(CASE WHEN DATE(cr.submission_date) >= DATE('now', '-7 days') THEN 1 END) as week_uploads,
//       MAX(cr.submission_date) as last_activity
//     FROM users u
//     JOIN hub_assignments ha ON u.id = ha.user_id
//     JOIN hubs h ON ha.hub_id = h.id
//     LEFT JOIN cleaning_reports cr ON u.email = cr.user_email
//     WHERE u.role = 'ground' 
//     AND ha.hub_id IN (
//       SELECT hub_id FROM hub_assignments WHERE user_id = ? AND role = 'yard_manager'
//     )
//     GROUP BY u.id, u.email, ha.hub_id, h.name
//     ORDER BY today_uploads DESC, week_uploads DESC
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Error loading worker activity:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json(rows || []);
//   });
// });
// // Comprehensive yard manager statistics
// app.get('/yard-manager-stats', requireAuth('yard_manager'), (req, res) => {
//   // Returns today's uploads, pending reviews, weekly totals, overdue items
// });

// // Recent uploads with audit information
// app.get('/yard-recent-uploads', requireAuth('yard_manager'), (req, res) => {
//   // Returns detailed upload history with audit status and ratings
// });

// // Ground worker performance tracking
// app.get('/ground-worker-activity', requireAuth('yard_manager'), (req, res) => {
//   // Returns individual worker metrics and productivity data
// });
// // Hub performance leaderboard
// app.get('/hub-performance-leaderboard', requireAuth('yard_manager'), (req, res) => {
//   // Returns ranked hub performance with scores and badges
// });

// // Performance comments system
// app.post('/hub-performance-comment', requireAuth('yard_manager'), (req, res) => {
//   // Allows adding operational comments and notes
// });

// // Achievement tracking
// app.get('/hub-achievements/:hubId', requireAuth('yard_manager'), (req, res) => {
//   // Returns achievement history and current badges
// });
// // NEW: Comprehensive yard manager dashboard statistics
// app.get('/yard-dashboard-stats', requireAuth('yard_manager'), (req, res) => {
//   db.serialize(() => {
//     let stats = {};
    
//     // Today's video uploads for yard manager's hubs
//     db.get(`
//       SELECT COUNT(*) as count FROM cleaning_reports r
//       JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//       WHERE ha.user_id = ? AND ha.role = 'yard_manager' 
//       AND DATE(r.submission_date) = DATE('now')
//     `, [req.session.userId], (err, row) => {
//       stats.today_uploads = err ? 0 : (row.count || 0);
      
//       // Pending review count for yard manager's hubs
//       db.get(`
//         SELECT COUNT(*) as count FROM cleaning_reports r
//         JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//         WHERE ha.user_id = ? AND ha.role = 'yard_manager' 
//         AND r.audit_status = 'pending'
//       `, [req.session.userId], (err, row) => {
//         stats.pending_review = err ? 0 : (row.count || 0);
        
//         // This week's uploads for yard manager's hubs
//         db.get(`
//           SELECT COUNT(*) as count FROM cleaning_reports r
//           JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//           WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//           AND DATE(r.submission_date) >= DATE('now', '-7 days')
//         `, [req.session.userId], (err, row) => {
//           stats.week_uploads = err ? 0 : (row.count || 0);
          
//           // Cars assigned but no videos uploaded (overdue)
//           db.get(`
//             SELECT COUNT(*) as count FROM car_assignments ca
//             LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
//             JOIN hub_assignments ha ON ca.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//             WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//             AND cr.id IS NULL AND julianday('now') - julianday(ca.assigned_at) > 2
//           `, [req.session.userId], (err, row) => {
//             stats.overdue_videos = err ? 0 : (row.count || 0);
            
//             // Average audit rating for yard manager's hubs
//             db.get(`
//               SELECT AVG(r.audit_rating) as avg_rating FROM cleaning_reports r
//               JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//               WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//               AND r.audit_rating IS NOT NULL AND r.audit_rating > 0
//             `, [req.session.userId], (err, row) => {
//               stats.avg_rating = err ? 0 : (Math.round((row.avg_rating || 0) * 10) / 10);
//               res.json(stats);
//             });
//           });
//         });
//       });
//     });
//   });
// });
// // NEW: Get all video assignments for yard manager's hubs
// app.get('/yard-video-assignments', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT 
//       ca.id, ca.reg_no, ca.hub_location, ca.reason, ca.assigned_at,
//       cr.id as report_id, cr.submission_date, cr.audit_status, cr.audit_rating,
//       cr.user_email as ground_worker,
//       CASE 
//         WHEN cr.id IS NOT NULL THEN 'uploaded'
//         WHEN julianday('now') - julianday(ca.assigned_at) > 2 THEN 'overdue'
//         ELSE 'pending'
//       END as status
//     FROM car_assignments ca
//     JOIN hub_assignments ha ON ca.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//     LEFT JOIN cleaning_reports cr ON ca.reg_no = cr.reg_no
//     WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//     ORDER BY ca.assigned_at DESC
//     LIMIT 100
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Video assignments error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json(rows || []);
//   });
// });
// // NEW: Get audit performance ratings for yard manager's hubs
// app.get('/yard-performance-ratings', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT 
//       r.reg_no, r.hub_location, r.user_email as ground_worker,
//       r.cleaning_date, r.submission_date,
//       r.audit_status, r.audit_rating, r.audit_notes,
//       strftime('%Y-%m', r.submission_date) as month_year
//     FROM cleaning_reports r
//     JOIN hub_assignments ha ON r.hub_location = (SELECT name FROM hubs WHERE id = ha.hub_id)
//     WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//     AND r.audit_status IN ('approved', 'rejected')
//     AND r.audit_rating IS NOT NULL
//     ORDER BY r.submission_date DESC
//     LIMIT 50
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Performance ratings error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json(rows || []);
//   });
// });
// // NEW: Enhanced ground worker activity and performance
// app.get('/yard-worker-performance', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT 
//       u.email as worker_email,
//       h.name as hub_name,
//       COUNT(CASE WHEN DATE(cr.submission_date) = DATE('now') THEN 1 END) as today_uploads,
//       COUNT(CASE WHEN DATE(cr.submission_date) >= DATE('now', '-7 days') THEN 1 END) as week_uploads,
//       COUNT(CASE WHEN DATE(cr.submission_date) >= DATE('now', '-30 days') THEN 1 END) as month_uploads,
//       AVG(CASE WHEN cr.audit_rating IS NOT NULL THEN cr.audit_rating END) as avg_rating,
//       COUNT(CASE WHEN cr.audit_status = 'approved' THEN 1 END) as approved_count,
//       COUNT(CASE WHEN cr.audit_status = 'rejected' THEN 1 END) as rejected_count,
//       MAX(cr.submission_date) as last_upload,
//       COUNT(cr.id) as total_uploads
//     FROM users u
//     JOIN hub_assignments ha ON u.id = ha.user_id
//     JOIN hubs h ON ha.hub_id = h.id
//     LEFT JOIN cleaning_reports cr ON u.email = cr.user_email AND cr.hub_location = h.name
//     WHERE u.role = 'ground' 
//     AND ha.hub_id IN (
//       SELECT hub_id FROM hub_assignments 
//       WHERE user_id = ? AND role = 'yard_manager'
//     )
//     GROUP BY u.id, u.email, h.name
//     ORDER BY today_uploads DESC, avg_rating DESC
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Worker performance error:', err);
//       return res.status(500).json({ error: err.message });
//     }
    
//     const formatted = rows.map(row => ({
//       ...row,
//       avg_rating: row.avg_rating ? Math.round(row.avg_rating * 10) / 10 : null,
//       performance_score: calculatePerformanceScore(row)
//     }));
    
//     res.json(formatted);
//   });
// });

// // Helper function for performance calculation
// function calculatePerformanceScore(worker) {
//   let score = 0;
  
//   // Rating component (40% weight)
//   if (worker.avg_rating) {
//     score += (worker.avg_rating / 5) * 40;
//   }
  
//   // Upload frequency (30% weight)
//   if (worker.week_uploads >= 5) score += 30;
//   else if (worker.week_uploads >= 3) score += 20;
//   else if (worker.week_uploads >= 1) score += 10;
  
//   // Approval rate (30% weight)
//   if (worker.total_uploads > 0) {
//     const approvalRate = worker.approved_count / worker.total_uploads;
//     score += approvalRate * 30;
//   }
  
//   return Math.round(score);
// }
// // NEW: Add comments for hub issues (manpower shortage, etc.)
// app.post('/yard-add-comment', requireAuth('yard_manager'), (req, res) => {
//   const { hub_id, comment_type, comment_text, priority } = req.body;
  
//   if (!hub_id || !comment_text) {
//     return res.status(400).json({ error: 'Hub ID and comment text are required' });
//   }
  
//   db.run(`
//     INSERT INTO yard_comments (hub_id, user_id, comment_type, comment_text, priority, created_at)
//     VALUES (?, ?, ?, ?, ?, datetime('now'))
//   `, [hub_id, req.session.userId, comment_type || 'general', comment_text, priority || 'medium'], 
//   function(err) {
//     if (err) {
//       console.error('Add comment error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json({ success: true, comment_id: this.lastID });
//   });
// });

// // NEW: Get comments for yard manager's hubs
// app.get('/yard-comments', requireAuth('yard_manager'), (req, res) => {
//   db.all(`
//     SELECT 
//       yc.id, yc.comment_type, yc.comment_text, yc.priority, yc.created_at,
//       h.name as hub_name, h.location as hub_location,
//       u.email as created_by
//     FROM yard_comments yc
//     JOIN hubs h ON yc.hub_id = h.id
//     JOIN users u ON yc.user_id = u.id
//     WHERE yc.hub_id IN (
//       SELECT hub_id FROM hub_assignments 
//       WHERE user_id = ? AND role = 'yard_manager'
//     )
//     ORDER BY yc.created_at DESC
//     LIMIT 50
//   `, [req.session.userId], (err, rows) => {
//     if (err) {
//       console.error('Get comments error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     res.json(rows || []);
//   });
// });
// // ===== GROUND WORKER VIDEO ENHANCEMENT ENDPOINTS =====

// // Handle video blob uploads from browser recording
// app.post('/upload-video-blob', 
//     requireAuth('ground'),
//     upload.single('video_blob'),
//     (req, res) => {
//         try {
//             const { video_type, reg_no, geo_lat, geo_lng, timestamp } = req.body;
            
//             if (!req.file) {
//                 return res.status(400).json({ error: 'No video file received' });
//             }
            
//             console.log(`Video blob uploaded: ${video_type} for ${reg_no}`);
            
//             res.json({ 
//                 success: true, 
//                 path: req.file.path,
//                 filename: req.file.filename,
//                 size: req.file.size,
//                 message: 'Video blob uploaded successfully' 
//             });
            
//         } catch (error) {
//             console.error('Video blob upload error:', error);
//             res.status(500).json({ error: 'Upload failed: ' + error.message });
//         }
//     }
// );

// // Get ground worker dashboard statistics
// app.get('/ground-stats', requireAuth('ground'), (req, res) => {
//     db.serialize(() => {
//         let stats = {};
        
//         // Today's uploads
//         db.get(`
//             SELECT COUNT(*) as count 
//             FROM cleaning_reports 
//             WHERE user_email = ? AND DATE(submission_date) = DATE('now')
//         `, [req.session.email], (err, row) => {
//             stats.today_uploads = err ? 0 : (row.count || 0);
            
//             // Total uploads
//             db.get(`
//                 SELECT COUNT(*) as count 
//                 FROM cleaning_reports 
//                 WHERE user_email = ?
//             `, [req.session.email], (err, row) => {
//                 stats.total_uploads = err ? 0 : (row.count || 0);
                
//                 // Average rating
//                 db.get(`
//                     SELECT AVG(audit_rating) as avg_rating 
//                     FROM cleaning_reports 
//                     WHERE user_email = ? AND audit_rating > 0
//                 `, [req.session.email], (err, row) => {
//                     stats.avg_rating = err ? 0 : (row.avg_rating || 0);
                    
//                     res.json(stats);
//                 });
//             });
//         });
//     });
// });
// // Enhanced ground worker statistics endpoint
// app.get('/ground-stats', requireAuth('ground'), (req, res) => {
//     db.serialize(() => {
//         let stats = {};
        
//         // Today's uploads
//         db.get(`
//             SELECT COUNT(*) as count 
//             FROM cleaning_reports 
//             WHERE user_email = ? AND DATE(submission_date) = DATE('now')
//         `, [req.session.email], (err, row) => {
//             stats.today_uploads = err ? 0 : (row.count || 0);
            
//             // Total uploads
//             db.get(`
//                 SELECT COUNT(*) as count 
//                 FROM cleaning_reports 
//                 WHERE user_email = ?
//             `, [req.session.email], (err, row) => {
//                 stats.total_uploads = err ? 0 : (row.count || 0);
                
//                 // Average rating
//                 db.get(`
//                     SELECT AVG(audit_rating) as avg_rating 
//                     FROM cleaning_reports 
//                     WHERE user_email = ? AND audit_rating > 0
//                 `, [req.session.email], (err, row) => {
//                     stats.avg_rating = err ? 0 : (Math.round((row.avg_rating || 0) * 10) / 10);
                    
//                     res.json(stats);
//                 });
//             });
//         });
//     });
// });
// app.get('/ground-stats', requireAuth('ground'), (req, res) => {
//     db.serialize(() => {
//         let stats = {};
        
//         db.get(`
//             SELECT COUNT(*) as count 
//             FROM cleaning_reports 
//             WHERE user_email = ? AND DATE(submission_date) = DATE('now')
//         `, [req.session.email], (err, row) => {
//             stats.today_uploads = err ? 0 : (row.count || 0);
            
//             db.get(`
//                 SELECT COUNT(*) as count 
//                 FROM cleaning_reports 
//                 WHERE user_email = ?
//             `, [req.session.email], (err, row) => {
//                 stats.total_uploads = err ? 0 : (row.count || 0);
//                 res.json(stats);
//             });
//         });
//     });
// });
// // ===== ADMIN ENDPOINTS FOR YARD MANAGER ASSIGNMENT =====

// // Get all yard managers for admin assignment

// // ===== ADMIN ENDPOINTS FOR YARD MANAGER ASSIGNMENT =====

// // Get all yard managers for admin assignment

// // Assign yard manager to hub


// // Remove yard manager from hub
// // Fix remove yard manager endpoint - UPDATED VERSION



// // ===== YARD MANAGER ENDPOINTS =====

// // Get uploaded videos for yard manager's assigned hubs
// app.get('/yard-manager-videos', requireAuth('yard_manager'), (req, res) => {
//     db.all(`
//         SELECT 
//             cr.id, cr.reg_no, cr.hub_location, cr.cleaning_date,
//             cr.exterior_video_path, cr.interior_video_path,
//             cr.submission_date, cr.user_email as ground_worker,
//             cr.audit_status, cr.audit_rating, cr.audit_notes,
//             h.name as hub_name, h.location as hub_location_full
//         FROM cleaning_reports cr
//         JOIN hubs h ON cr.hub_location = h.name
//         JOIN hub_assignments ha ON h.id = ha.hub_id
//         WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//         ORDER BY cr.submission_date DESC
//         LIMIT 100
//     `, [req.session.userId], (err, rows) => {

//         ? Math.round((r.total_cleaned / r.total_assigned) * 100)
//         : 0
//     })));
//   });
// });

// // Start server
// app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));


// db.run(`CREATE TABLE IF NOT EXISTS yard_comments (
//   id INTEGER PRIMARY KEY AUTOINCREMENT,
//   hub_id INTEGER NOT NULL,
//   user_id INTEGER NOT NULL,
//   comment_type TEXT DEFAULT 'general',
//   comment_text TEXT NOT NULL,
//   priority TEXT DEFAULT 'medium',
//   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//   FOREIGN KEY(hub_id) REFERENCES hubs(id),
//   FOREIGN KEY(user_id) REFERENCES users(id)
// )`);

//   db.run(`CREATE TABLE IF NOT EXISTS users (
//     id               INTEGER PRIMARY KEY AUTOINCREMENT,
//     email            TEXT UNIQUE NOT NULL,
//     role             TEXT NOT NULL DEFAULT 'ground',
//     hub_location     TEXT,
//     vehicle_reg_no   TEXT
//   )`);
  
//   // Create car_assignments table with UNIQUE constraint
//   db.run(`CREATE TABLE IF NOT EXISTS car_assignments (
//     id           INTEGER PRIMARY KEY AUTOINCREMENT,
//     reg_no       TEXT NOT NULL UNIQUE,
//     hub_location TEXT NOT NULL,
//     reason       TEXT NOT NULL DEFAULT 'unknown',
//     assigned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//   )`);
  
//   // Cleaning reports
//   db.run(`CREATE TABLE IF NOT EXISTS cleaning_reports (
//     id                  INTEGER PRIMARY KEY AUTOINCREMENT,
//     reg_no              TEXT NOT NULL,
//     hub_location        TEXT NOT NULL,
//     cleaning_date       TEXT NOT NULL,
//     exterior_video_path TEXT NOT NULL,
//     interior_video_path TEXT NOT NULL,
//     submission_date     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     audit_status        TEXT    DEFAULT 'pending',
//     audit_rating        INTEGER DEFAULT 0,
//     audit_notes         TEXT,
//     user_email          TEXT NOT NULL,
//     reason              TEXT    NOT NULL DEFAULT 'unknown'
//   )`);
  
//   // Hubs table with Google Sheets ID
//   db.run(`CREATE TABLE IF NOT EXISTS hubs (
//     id    INTEGER PRIMARY KEY AUTOINCREMENT,
//     name  TEXT UNIQUE NOT NULL,
//     location TEXT NOT NULL,
//     sheet_id TEXT NOT NULL
//   )`);
  
//   // Hub assignments (yard manager, auditor, ground)
//   db.run(`CREATE TABLE IF NOT EXISTS hub_assignments (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     hub_id INTEGER NOT NULL,
//     user_id INTEGER NOT NULL,
//     role TEXT NOT NULL,
//     FOREIGN KEY(hub_id) REFERENCES hubs(id),
//     FOREIGN KEY(user_id) REFERENCES users(id)
//   )`);
  
//   // No video reports
//   db.run(`CREATE TABLE IF NOT EXISTS no_video_reports (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     hub_id INTEGER NOT NULL,
//     reason TEXT NOT NULL,
//     reported_by INTEGER NOT NULL,
//     reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     FOREIGN KEY(hub_id) REFERENCES hubs(id),
//     FOREIGN KEY(reported_by) REFERENCES users(id)
//   )`);
  
//   // Default admin
//   db.run(`INSERT OR IGNORE INTO users (email,role) VALUES (?,?)`,
//     ['aditya.thakur@cariotauto.com', 'admin']);
// });

// // Function to sync hubs from Google Sheets
// // Replace your existing syncHubsFromGoogleSheets function with this:
// // Load yard manager assignments - FIXED VERSION


// async function syncHubsFromGoogleSheets() {
//   try {
//     if (!fs.existsSync('credentials.json')) {
//       console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
//       return;
//     }
    
//     const auth = new google.auth.GoogleAuth({
//       keyFile: 'credentials.json',
//       scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
//     });

//     const sheets = google.sheets({ version: 'v4', auth });
//     const response = await sheets.spreadsheets.values.get({
//       spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
//       range: 'Sheet1!A2:E',
//     });

//     const rows = response.data.values;
    
//     return new Promise((resolve, reject) => {
//       db.serialize(() => {
//         // **Clear the hubs table before importing**
//         db.run('DELETE FROM hubs');
        
//         if (rows && rows.length) {
//           db.run('BEGIN TRANSACTION');
          
//           rows.forEach(row => {
//             const [name, location, yardManagerEmail, auditorEmail, groundTeamEmail] = row;
            
//             if (location) {
//               db.run(`INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`, 
//                 [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'], function(err) {
//                 if (err) {
//                   console.error(`Hub sync error: ${err.message}`);
//                   return;
//                 }
                
//                 const hubId = this.lastID;
//                 assignUserToHub(yardManagerEmail, hubId, 'yard_manager');
//                 assignUserToHub(auditorEmail, hubId, 'auditor');
//                 assignUserToHub(groundTeamEmail, hubId, 'ground');
//               });
//             }
//           });
          
//           db.run('COMMIT', (err) => {
//             if (err) {
//               console.error('Commit error:', err);
//               reject(err);
//             } else {
//               console.log(`✅ Imported ${rows.length} hubs successfully`);
//               resolve();
//             }
//           });
//         } else {
//           console.log('✅ No hubs found in sheet');
//           resolve();
//         }
//       });
//     });
//   } catch (err) {
//     console.error('❌ Google Sheets sync error:', err.message);
//     throw err;
//   }
// }


// // Function to sync car assignments from Google Sheets
// // Function to sync car assignments from Google Sheets
// // FIXED: Complete Google Sheets sync function with proper cleanup
// async function syncHubsFromGoogleSheets() {
//   try {
//     if (!fs.existsSync('credentials.json')) {
//       console.error('❌ credentials.json file not found. Google Sheets sync skipped.');
//       return;
//     }
    
//     const auth = new google.auth.GoogleAuth({
//       keyFile: 'credentials.json',
//       scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
//     });

//     const sheets = google.sheets({ version: 'v4', auth });
//     const response = await sheets.spreadsheets.values.get({
//       spreadsheetId: '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM',
//       range: 'Sheet1!A2:E',
//     });

//     const rows = response.data.values;
    
//     return new Promise((resolve, reject) => {
//       db.serialize(() => {
//         console.log('🔄 Starting complete hub sync with cleanup...');
        
//         db.run('BEGIN TRANSACTION');
        
//         // *** CRITICAL FIX: Clean up ALL existing hub assignments first ***
//         db.run('DELETE FROM hub_assignments WHERE role IN (?, ?, ?)', 
//           ['yard_manager', 'auditor', 'ground'], (err) => {
//           if (err) {
//             console.error('❌ Error cleaning hub assignments:', err);
//             db.run('ROLLBACK');
//             return reject(err);
//           }
//           console.log('✅ Cleaned existing hub assignments');
          
//           // Clear the hubs table
//           db.run('DELETE FROM hubs', (err) => {
//             if (err) {
//               console.error('❌ Error cleaning hubs:', err);
//               db.run('ROLLBACK');
//               return reject(err);
//             }
//             console.log('✅ Cleaned existing hubs');
            
//             if (rows && rows.length) {
//               let processedCount = 0;
              
//               rows.forEach(row => {
//                 const [name, location, yardManagerEmail, auditorEmail, groundTeamEmail] = row;
                
//                 if (location && name) {
//                   db.run(`INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`, 
//                     [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'], function(err) {
//                     if (err) {
//                       console.error(`❌ Hub sync error for ${name}:`, err.message);
//                     } else {
//                       const hubId = this.lastID;
//                       console.log(`✅ Created hub: ${name} (ID: ${hubId})`);
                      
//                       // Assign users to the new hub (only if email provided)
//                       if (yardManagerEmail && yardManagerEmail.trim()) {
//                         assignUserToHub(yardManagerEmail.trim(), hubId, 'yard_manager');
//                         console.log(`  → Assigned yard manager: ${yardManagerEmail}`);
//                       }
//                       if (auditorEmail && auditorEmail.trim()) {
//                         assignUserToHub(auditorEmail.trim(), hubId, 'auditor');
//                         console.log(`  → Assigned auditor: ${auditorEmail}`);
//                       }
//                       if (groundTeamEmail && groundTeamEmail.trim()) {
//                         assignUserToHub(groundTeamEmail.trim(), hubId, 'ground');
//                         console.log(`  → Assigned ground worker: ${groundTeamEmail}`);
//                       }
//                     }
                    
//                     processedCount++;
//                     if (processedCount === rows.length) {
//                       db.run('COMMIT', (err) => {
//                         if (err) {
//                           console.error('❌ Commit error:', err);
//                           reject(err);
//                         } else {
//                           console.log(`✅ Successfully imported ${rows.length} hubs with clean assignments`);
//                           resolve();
//                         }
//                       });
//                     }
//                   });
//                 } else {
//                   processedCount++;
//                   if (processedCount === rows.length) {
//                     db.run('COMMIT', (err) => {
//                       if (err) {
//                         console.error('❌ Commit error:', err);
//                         reject(err);
//                       } else {
//                         console.log(`✅ Successfully imported ${rows.length} hubs with clean assignments`);
//                         resolve();
//                       }
//                     });
//                   }
//                 }
//               });
//             } else {
//               console.log('✅ No hubs found in sheet, sync completed');
//               db.run('COMMIT');
//               resolve();
//             }
//           });
//         });
//       });
//     });
//   } catch (err) {
//     console.error('❌ Google Sheets sync error:', err.message);
//     throw err;
//   }
// }




// function assignUserToHub(email, hubId, role) {
//   if (!email || !hubId) {
//     console.log(`Skipping assignment: email=${email}, hubId=${hubId}`);
//     return;
//   }
  
//   db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, user) => {
//     if (err) {
//       console.error(`Database error: ${err.message}`);
//       return;
//     }
    
//     if (user) {
//       db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
//               VALUES (?, ?, ?)`, [hubId, user.id, role], (err) => {
//         if (err) console.error(`Error assigning ${email} to hub:`, err);
//       });
//     } else {
//       // Create user if not exists
//       db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function(err) {
//         if (err) {
//           console.error(`Error creating user ${email}:`, err);
//           return;
//         }
//         const userId = this.lastID;
//         db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) 
//                 VALUES (?, ?, ?)`, [hubId, userId, role], (err) => {
//           if (err) console.error(`Error assigning new user to hub:`, err);
//         });
//       });
//     }
//   });
// }

// // Manual hub assignment for specific users
// async function assignSpecificHubs() {
//   try {
//     // Get Agra hub
//     const agraHub = await new Promise((resolve) => {
//       db.get("SELECT id FROM hubs WHERE location LIKE '%Agra%'", (err, row) => {
//         if (err) console.error(err);
//         resolve(row?.id);
//       });
//     });
    
//     if (agraHub) {
//       assignUserToHub('kanu6280@gmail.com', agraHub, 'yard_manager');
//       console.log(`✅ Assigned Agra hub to kanu6280@gmail.com`);
//     } else {
//       console.error('Agra hub not found');
//     }

//     // Get Ahmedabad hub
//     const ahmedabadHub = await new Promise((resolve) => {
//       db.get("SELECT id FROM hubs WHERE location LIKE '%Ahmedabad%'", (err, row) => {
//         if (err) console.error(err);
//         resolve(row?.id);
//       });
//     });
    
//     if (ahmedabadHub) {
//       assignUserToHub('business.uut@gmail.com', ahmedabadHub, 'yard_manager');
//       console.log(`✅ Assigned Ahmedabad hub to business.uut@gmail.com`);
//     } else {
//       console.error('Ahmedabad hub not found');
//     }
//   } catch (err) {
//     console.error('Manual assignment error:', err);
//   }
// }

// // Sync hubs on startup
// syncHubsFromGoogleSheets()
//   .then(assignSpecificHubs)
//   .catch(console.error);

// // Middleware for role-based authentication
// function requireAuth(role) {
//   return (req, res, next) => {
//     if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
//     if (role && req.session.role !== role) return res.status(403).json({ error: 'Forbidden' });
//     next();
//   };
// }

// // Google OAuth login
// app.post('/google-auth', async (req, res) => {
//   const { token } = req.body;
//   if (!token) return res.status(400).json({ error: 'No token' });
//   try {
//     const ticket = await client.verifyIdToken({ idToken: token, audience: CLIENT_ID });
//     const { email } = ticket.getPayload();
    
//     db.get(`SELECT * FROM users WHERE email=?`, [email], (err, user) => {
//       if (err) return res.status(500).json({ error: err.message });
      
//       // If user doesn't exist, create with default 'ground' role
//       const role = user ? user.role : 'ground';
//       const hub = user ? user.hub_location : null;
//       const vehicle = user ? user.vehicle_reg_no : null;
      
//       const finish = id => {
//         req.session.userId = id;
//         req.session.email = email;
//         req.session.role = role;
//         req.session.hub = hub;
//         req.session.vehicle_reg_no = vehicle;
//         res.json({ role, hub, vehicle });
//       };
      
//       if (!user) {
//         db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, role], function (err) {
//           if (err) return res.status(500).json({ error: err.message });
//           finish(this.lastID);
//         });
//       } else {
//         finish(user.id);
//       }
//     });
//   } catch {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// });
// // Get daily adherence for a hub (or all hubs)
// // Fixed adherence report endpoint

// // ===== MISSING ENDPOINT - ADD THIS =====

// // Get all yard managers for admin assignment - FIXED VERSION
// // Get all yard managers for admin assignment - FIXED VERSION
// // app.get('/admin-yard-managers', requireAuth('admin'), (req, res) => {
// //     const query = `
// //         SELECT 
// //             u.id, 
// //             u.email, 
// //             u.role,
// //             GROUP_CONCAT(h.name || ' (' || h.location || ')') as assigned_hubs,
// //             COUNT(h.id) as hub_count
// //         FROM users u
// //         LEFT JOIN hub_assignments ha ON u.id = ha.user_id AND ha.role = 'yard_manager'
// //         LEFT JOIN hubs h ON ha.hub_id = h.id
// //         WHERE u.role = 'yard_manager'
// //         GROUP BY u.id, u.email, u.role
// //         ORDER BY u.email
// //     `;
    
// //     db.all(query, [], (err, rows) => {
// //         if (err) {
// //             console.error('Error fetching yard managers:', err);
// //             return res.status(500).json({ error: err.message });
// //         }
        
// //         // Clean up the data to ensure only hub names appear
// //         const cleanedRows = rows.map(row => ({
// //             id: row.id,
// //             email: row.email,
// //             role: row.role,
// //             assigned_hubs: row.assigned_hubs || null,
// //             hub_count: row.hub_count || 0
// //         }));
        
// //         res.json(cleanedRows);
// //     });
// // });
// // ===== MISSING ENDPOINTS - ADD THESE TO YOUR SERVER.JS =====

// // Get dashboard statistics for yard manager's assigned hubs
// app.get('/yard-manager-dashboard-stats', requireAuth('yard_manager'), (req, res) => {
//     db.serialize(() => {
//         let stats = {};
        
//         // Total videos uploaded to yard manager's hubs
//         db.get(`
//             SELECT COUNT(*) as count FROM cleaning_reports cr
//             JOIN hubs h ON cr.hub_location = h.name
//             JOIN hub_assignments ha ON h.id = ha.hub_id
//             WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//         `, [req.session.userId], (err, row) => {
//             stats.total_videos = err ? 0 : (row.count || 0);
            
//             // Today's uploads
//             db.get(`
//                 SELECT COUNT(*) as count FROM cleaning_reports cr
//                 JOIN hubs h ON cr.hub_location = h.name
//                 JOIN hub_assignments ha ON h.id = ha.hub_id
//                 WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//                 AND DATE(cr.submission_date) = DATE('now')
//             `, [req.session.userId], (err, row) => {
//                 stats.today_uploads = err ? 0 : (row.count || 0);
                
//                 // Pending audits
//                 db.get(`
//                     SELECT COUNT(*) as count FROM cleaning_reports cr
//                     JOIN hubs h ON cr.hub_location = h.name
//                     JOIN hub_assignments ha ON h.id = ha.hub_id
//                     WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//                     AND cr.audit_status = 'pending'
//                 `, [req.session.userId], (err, row) => {
//                     stats.pending_audits = err ? 0 : (row.count || 0);
                    
//                     // Approved videos
//                     db.get(`
//                         SELECT COUNT(*) as count FROM cleaning_reports cr
//                         JOIN hubs h ON cr.hub_location = h.name
//                         JOIN hub_assignments ha ON h.id = ha.hub_id
//                         WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//                         AND cr.audit_status = 'approved'
//                     `, [req.session.userId], (err, row) => {
//                         stats.approved_videos = err ? 0 : (row.count || 0);
                        
//                         // Average rating
//                         db.get(`
//                             SELECT AVG(cr.audit_rating) as avg_rating FROM cleaning_reports cr
//                             JOIN hubs h ON cr.hub_location = h.name
//                             JOIN hub_assignments ha ON h.id = ha.hub_id
//                             WHERE ha.user_id = ? AND ha.role = 'yard_manager'
//                             AND cr.audit_rating IS NOT NULL AND cr.audit_rating > 0
//                         `, [req.session.userId], (err, row) => {
//                             stats.avg_rating = err ? 0 : (Math.round((row.avg_rating || 0) * 10) / 10);
//                             res.json(stats);
//                         });
//                     });
//                 });
//             });
//         });
//     });
// });
// // ===== ADD THESE ENDPOINTS TO SERVER.JS =====

// // Get all yard managers for admin assignment
// app.get('/admin-yard-managers', requireAuth('admin'), (req, res) => {
//     db.all(`
//         SELECT 
//             u.id, u.email, u.role,
//             GROUP_CONCAT(h.name || ' (' || h.location || ')') as assigned_hubs
//         FROM users u
//         LEFT JOIN hub_assignments ha ON u.id = ha.user_id AND ha.role = 'yard_manager'
//         LEFT JOIN hubs h ON ha.hub_id = h.id
//         WHERE u.role = 'yard_manager'
//         GROUP BY u.id, u.email, u.role
//         ORDER BY u.email
//     `, [], (err, rows) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(rows || []);
//     });
// });

// // Assign yard manager to hub
// app.post('/admin-assign-yard-manager', requireAuth('admin'), (req, res) => {
//     const { email, hub_id } = req.body;
    
//     if (!email || !hub_id) {
//         return res.status(400).json({ error: 'Email and hub_id are required' });
//     }
    
//     // Create user if doesn't exist
//     db.get(`SELECT id FROM users WHERE email = ? AND role = 'yard_manager'`, [email], (err, user) => {
//         if (err) return res.status(500).json({ error: err.message });
        
//         if (!user) {
//             db.run(`INSERT INTO users (email, role) VALUES (?, 'yard_manager')`, [email], function(err) {
//                 if (err) return res.status(500).json({ error: err.message });
//                 assignToHub(this.lastID, hub_id, res);
//             });
//         } else {
//             assignToHub(user.id, hub_id, res);
//         }
//     });
    
//     function assignToHub(userId, hubId, res) {
//         db.run(`INSERT OR REPLACE INTO hub_assignments (hub_id, user_id, role) VALUES (?, ?, 'yard_manager')`, 
//             [hubId, userId], (err) => {
//             if (err) return res.status(500).json({ error: err.message });
//             res.json({ success: true, message: 'Yard manager assigned successfully' });
//         });
//     }
// });

// // Remove yard manager assignment
// app.delete('/admin-remove-yard-manager', requireAuth('admin'), (req, res) => {
//     const { email } = req.body;
    
//     if (!email) {
//         return res.status(400).json({ error: 'Email is required' });
//     }
    
//     db.get(`SELECT id FROM users WHERE email = ? AND role = 'yard_manager'`, [email], (err, user) => {
//         if (err) return res.status(500).json({ error: err.message });
//         if (!user) return res.status(404).json({ error: 'Yard manager not found' });
        
//         db.run(`DELETE FROM hub_assignments WHERE user_id = ? AND role = 'yard_manager'`, 
//             [user.id], (err) => {
//             if (err) return res.status(500).json({ error: err.message });
//             res.json({ success: true, message: 'All assignments removed' });
//         });
//     });
// });

// app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));






























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
                  db.run(`INSERT INTO hubs (name, location, sheet_id) VALUES (?, ?, ?)`, 
                    [name, location, '1Of8Wl0xnLdtQb2MLeaYXvw_ZX9RKI1o1yrhxNZlyhnM'], function(err) {
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

app.get('/video/interior/:id', (req, res) => {
  db.get(`SELECT interior_video_path FROM cleaning_reports WHERE id = ?`,
    [req.params.id], (err, row) => {
      if (err || !row) return res.status(404).json({ error: 'Video not found' });

      const videoPath = row.interior_video_path;
      
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

// Get ground worker statistics
app.get('/ground-stats', requireAuth('ground'), (req, res) => {
  db.serialize(() => {
    let stats = {};
    
    db.get(`
        SELECT COUNT(*) as count 
        FROM cleaning_reports 
        WHERE user_email = ? AND DATE(submission_date) = DATE('now')
    `, [req.session.email], (err, row) => {
        stats.today_uploads = err ? 0 : (row.count || 0);
        
        db.get(`
            SELECT COUNT(*) as count 
            FROM cleaning_reports 
            WHERE user_email = ?
        `, [req.session.email], (err, row) => {
            stats.total_uploads = err ? 0 : (row.count || 0);
            res.json(stats);
        });
    });
  });
});

// Start server
console.log("✅ Server is ready and listening...");
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));
});