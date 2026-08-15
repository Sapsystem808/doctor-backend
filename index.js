
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');


const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const supabase = createClient(supabaseUrl, supabaseKey);
let serviceAccount;
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
        serviceAccount = require('./serviceAccountKey.json');
    }
} catch (error) {
    console.error("❌ Service Account Error - Check Env Vars", error);
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();


const verifyAppCheck = async (req, res, next) => {
    const appCheckToken = req.headers['x-firebase-appcheck'];
    if (!appCheckToken) {
        console.warn("⚠️ App Check: No token provided");
        return next();
    }
    try {
        await admin.appCheck().verifyToken(appCheckToken);
        next();
    } catch (err) {
        console.warn("⚠️ App Check: Invalid token", err.message);
        next();
    }
};
const app = express();

const registerFacultyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "⏳ محاولات كثيرة جداً، حاول بعد 15 دقيقة" },
    standardHeaders: true,
    legacyHeaders: false,
});

const ALLOWED_ORIGINS = [
    "https://smart-attendance-pro-doctor.web.app",
    "https://smart-attendance-pro-doctor.firebaseapp.com",
    "https://smartattendancepro-code.github.io",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    "http://localhost:5503",
    "http://127.0.0.1:5503"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    }
}));
app.use(bodyParser.json());

const COLLEGE_COORDS = {
    lat: 30.385873919506743,
    lng: 30.488794680472196
};
const MAX_DISTANCE_KM = 2.5;


const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Missing Token" });
    }
    try {
        const idToken = authHeader.split('Bearer ')[1];
        req.user = await admin.auth().verifyIdToken(idToken);
        next();
    } catch (error) {
        return res.status(403).json({ error: "Invalid Token" });
    }
};

const verifyStaffRole = async (req, res, next) => {
    try {
        const uid = req.user.uid;
        const docSnap = await db.collection("faculty_members").doc(uid).get();

        if (docSnap.exists) {
            const userData = docSnap.data();
            if (userData.role === 'dean' || userData.role === 'doctor') {
                req.staffData = userData;
                return next();
            }
        }

        return res.status(403).json({ error: "Access Denied: Staff Only" });
    } catch (e) {
        res.status(500).json({ error: "Security Check Failed" });
    }
};

function calculateDistance(lat1, lon1, lat2, lon2) {
    if (!lat1 || !lon1 || !lat2 || !lon2) return 9999;
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

app.get('/', (req, res) => {
    res.status(200).send("🦅 Nursing System Backend is Running (Bulletproof V7 - Multi-College)");
});


app.post('/joinSessionSecure', verifyToken, verifyAppCheck, async (req, res) => {

    const perfStart = Date.now();
    try {
        const studentUID = req.user.uid;
        const { sessionDocID, gpsLat, gpsLng, deviceFingerprint, codeInput } = req.body;
        const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        if (!sessionDocID) return res.status(400).json({ error: "Missing Session ID" });

        // 🚀 جلب كل البيانات دفعة واحدة
        const sessionRef = db.collection('active_sessions').doc(sessionDocID);
        const studentRef = db.collection('user_registrations').doc(studentUID);
        const sensitiveRef = db.collection('user_registrations').doc(studentUID).collection('sensitive_info').doc('main');
        const participantRef = sessionRef.collection('participants').doc(studentUID);

        const [sessionSnap, studentSnap, sensitiveSnap, participantSnap] = await Promise.all([
            sessionRef.get(),
            studentRef.get(),
            sensitiveRef.get(),
            participantRef.get()
        ]);

        if (!sessionSnap.exists) return res.status(404).json({ error: "⛔ الجلسة غير موجودة." });
        if (!studentSnap.exists) return res.status(404).json({ error: "بيانات الطالب غير موجودة." });

        const sessionData = sessionSnap.data();
        const sData = studentSnap.data();
        const info = sData.registrationInfo || {};

        const isEmailVerified = req.user.email_verified;
        const isManuallyVerified = (sData.status === 'verified' || sData.manual_verification === true);

        if (!isEmailVerified && !isManuallyVerified) {
            return res.status(403).json({ error: "⛔ الحساب غير مفعل! يرجى تأكيد الإيميل أو مراجعة شؤون الطلاب." });
        }

        if (!sessionData.isActive || !sessionData.isDoorOpen) {
            return res.status(403).json({ error: "🔒 الباب مغلق حالياً." });
        }

        if (sessionData.sessionCode &&
            sessionData.sessionCode !== "------" &&
            sessionData.sessionCode !== "PAUSED") {
            if (!codeInput || String(codeInput).trim() !== String(sessionData.sessionCode).trim()) {
                return res.status(403).json({ error: "❌ كود الجلسة خاطئ." });
            }
        }

        let currentDist = calculateDistance(gpsLat, gpsLng, COLLEGE_COORDS.lat, COLLEGE_COORDS.lng);
        let isLocationValid = (currentDist <= MAX_DISTANCE_KM);

        let isDeviceMatch = true;
        const batch = db.batch();

        if (sensitiveSnap.exists) {
            const sensData = sensitiveSnap.data();
            const allowed = sensData.allowed_devices || (sensData.bound_device_id ? [sensData.bound_device_id] : []);
            if (deviceFingerprint && !allowed.includes(deviceFingerprint)) {
                isDeviceMatch = false;
            }
        } else {
            batch.set(sensitiveRef, {
                allowed_devices: [deviceFingerprint || "UNKNOWN_DEVICE"],
                bound_at: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
        }

        const trapReport = {
            is_in_range: isLocationValid,
            is_device_match: isDeviceMatch,
            gps_success: (gpsLat !== 0 && gpsLng !== 0),
            distance_km: Number(currentDist.toFixed(3)),
            ip_address: userIP,
            device_id_used: deviceFingerprint || "NO_ID",
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            process_time_ms: Date.now() - perfStart
        };

        let savedCount = participantSnap.exists ? (participantSnap.data().segment_count || 1) : 1;

        const sessionCollege = sessionData.college || "NURS";

        batch.set(participantRef, {
            id: info.studentID || "UNKNOWN",
            name: info.fullName || "Student",
            uid: studentUID,
            level: info.level || "-",
            group: info.group || "-",
            college: sessionCollege,
            status: "active",
            isSuspicious: !isDeviceMatch,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            trap_report: trapReport,
            avatarClass: sData.avatarClass || "fa-user",
            isUnruly: false,
            isUniformViolation: false,
            segment_count: savedCount
        });

        const subjectKey = (sessionData.allowedSubject || "General").replace(/[^\w\u0600-\u06FF]/g, '_');
        const statsRef = db.collection('student_stats').doc(studentUID);

        batch.set(statsRef, {
            [`attended.${subjectKey}`]: admin.firestore.FieldValue.increment(1),
            last_attendance: admin.firestore.FieldValue.serverTimestamp(),
            fullName: info.fullName,
            studentID: info.studentID,
            group: info.group || "عام",
            college: sessionCollege
        }, { merge: true });

        batch.update(studentRef, {
            attendanceCount: admin.firestore.FieldValue.increment(1)
        });

        await batch.commit();

        console.log(`⚡ FastJoin: ${Date.now() - perfStart}ms | User: ${info.fullName} | College: ${sessionCollege}`);

        try {
            await db.collection('user_registrations').doc(studentUID).set({
                liveState: {
                    status: 'active',
                    doctorUID: sessionDocID,
                    joinedAt: admin.firestore.FieldValue.serverTimestamp()
                }
            }, { merge: true });
        } catch (e) {
            console.warn('liveState update skipped:', e.message);
        }

        res.status(200).json({ success: true, message: "تم تسجيل الحضور ✅" });

    } catch (error) {
        console.error("🔥 Join Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر حاول مجدداً" });
    }
});


app.post('/api/closeSession', verifyToken, verifyStaffRole, verifyAppCheck, async (req, res) => {

    try {
        const doctorUID = req.user.uid;

        const sessionRef = db.collection('active_sessions').doc(doctorUID);
        const sessionSnap = await sessionRef.get();

        if (!sessionSnap.exists) {
            return res.status(404).json({ error: "لا توجد جلسة نشطة" });
        }

        const settings = sessionSnap.data();

        if (!settings.isActive) {
            return res.status(400).json({ error: "الجلسة مغلقة بالفعل" });
        }

        const sessionCollege = settings.college ||
            (req.staffData && req.staffData.college) ||
            "NURS";
        const sessionSisCode = settings.sisCode || "";

        const partsRef = db.collection('active_sessions').doc(doctorUID).collection('participants');
        const partsSnap = await partsRef.get();

        const now = new Date();
        const d = String(now.getDate()).padStart(2, '0');
        const m = String(now.getMonth() + 1).padStart(2, '0');
        const y = now.getFullYear();
        const fixedDateStr = `${d}/${m}/${y}`;
        const closeTimeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

        const rawSubject = settings.allowedSubject || "General";
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');

        const targetGroups = (req.body.resolvedGroups && req.body.resolvedGroups.length > 0)
            ? req.body.resolvedGroups
            : (settings.targetGroups && settings.targetGroups.length > 0)
                ? settings.targetGroups
                : ["General"];

        const currentDocName = settings.doctorName || "Doctor";

        const BATCH_LIMIT = 450;
        let currentBatch = db.batch();
        let opCounter = 0;
        const commitPromises = [];
        let processedCount = 0;

        const pushBatch = () => {
            commitPromises.push(currentBatch.commit());
            currentBatch = db.batch();
            opCounter = 0;
        };

        partsSnap.forEach(docSnap => {
            const p = docSnap.data();

            if (p.status === "active" || p.status === "on_break") {
                const recID = `${p.id}_${fixedDateStr.replace(/\//g, '-')}_${cleanSubKey}_${sessionCollege}`;
                const attRef = db.collection('attendance').doc(recID);

                let finalGroup = (p.group && p.group !== "General") ? p.group : targetGroups[0];
                let notesText = "منضبط";
                if (p.isUnruly) notesText = "غير منضبط - مشاغب";
                else if (p.isUniformViolation) notesText = "مخالفة زي";

                currentBatch.set(attRef, {
                    id: p.id,
                    name: p.name,
                    subject: rawSubject,
                    hall: settings.hall,
                    group: finalGroup,
                    college: sessionCollege,
                    date: fixedDateStr,
                    time_str: p.time_str || req.body.time_str || closeTimeStr,
                    segment_count: p.segment_count || 1,
                    notes: notesText,
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    status: "ATTENDED",
                    doctorUID: doctorUID,
                    doctorName: currentDocName,
                    feedback_status: "pending",
                    feedback_rating: 0,
                    isUnruly: p.isUnruly || false,
                    isUniformViolation: p.isUniformViolation || false,
                    sisCode: sessionSisCode
                });
                opCounter++;

                const studentStatsRef = db.collection('student_stats').doc(p.uid || p.id);
                let statsUpdate = {
                    group: finalGroup,
                    studentID: p.id,
                    college: sessionCollege,
                    last_updated: admin.firestore.FieldValue.serverTimestamp(),
                    attended: {
                        [cleanSubKey]: admin.firestore.FieldValue.increment(1)
                    }
                };
                if (p.isUnruly) statsUpdate.cumulative_unruly = admin.firestore.FieldValue.increment(1);
                if (p.isUniformViolation) statsUpdate.cumulative_uniform = admin.firestore.FieldValue.increment(1);

                currentBatch.set(studentStatsRef, statsUpdate, { merge: true });
                opCounter++;
                processedCount++;
            }

            currentBatch.delete(docSnap.ref);
            opCounter++;
            if (opCounter >= BATCH_LIMIT) pushBatch();
        });

        targetGroups.forEach(groupName => {
            if (!groupName) return;
            const groupRef = db.collection('groups_stats').doc(groupName);
            currentBatch.set(groupRef, {
                [`subjects.${cleanSubKey}.total_sessions_held`]: admin.firestore.FieldValue.increment(1),
                last_updated: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            opCounter++;
            if (opCounter >= BATCH_LIMIT) pushBatch();
        });

        const safeDateID = fixedDateStr.replace(/\//g, '-');
        targetGroups.forEach(grp => {
            const uniqueCounterID = `${safeDateID}_${cleanSubKey}_${grp}_${sessionCollege}`;
            const counterRef = db.collection('course_counters').doc(uniqueCounterID);
            currentBatch.set(counterRef, {
                subject: rawSubject,
                targetGroups: [grp],
                college: sessionCollege,
                date: fixedDateStr,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                doctorUID: doctorUID,
                academic_year: y.toString()
            });
            opCounter++;
            if (opCounter >= BATCH_LIMIT) pushBatch();
        });

        currentBatch.update(sessionRef, { isActive: false, isDoorOpen: false });
        opCounter++;
        if (opCounter > 0) commitPromises.push(currentBatch.commit());

        await Promise.all(commitPromises);

        try {
            const supabaseRecords = [];

            partsSnap.forEach(docSnap => {
                const p = docSnap.data();
                if (p.status === "active" || p.status === "on_break") {
                    let finalGroup = (p.group && p.group !== "General") ? p.group : targetGroups[0];
                    let notesText = p.isUnruly ? "غير منضبط - مشاغب" : (p.isUniformViolation ? "مخالفة زي" : "منضبط");

                    supabaseRecords.push({
                        student_id: p.id,
                        student_name: p.name,
                        subject_name: rawSubject,
                        college: sessionCollege,
                        hall: settings.hall || "",
                        target_group: finalGroup,
                        sis_code: sessionSisCode || "",
                        session_date: fixedDateStr,
                        attendance_time: p.time_str || req.body.time_str || closeTimeStr,
                        status: "ATTENDED",
                        is_unruly: p.isUnruly || false,
                        is_uniform_violation: p.isUniformViolation || false,
                        notes: notesText,
                        doctor_uid: doctorUID,
                        doctor_name: currentDocName,
                        is_recovered: false,
                        feedback_status: "pending",
                        feedback_rating: 0,
                        segment_count: p.segment_count || 1,
                        is_offline_sync: false,
                        doctor_avatar: settings.doctorAvatar || "",
                        level: p.level || "-",
                        group_name: finalGroup,
                        is_suspicious: p.isSuspicious || false,
                        trap_is_in_range: p.trap_report?.is_in_range ?? true,
                        trap_is_device_match: p.trap_report?.is_device_match ?? true,
                        trap_gps_success: p.trap_report?.gps_success ?? true,
                        trap_distance_km: p.trap_report?.distance_km ?? 0,
                    });
                }
            });

            if (supabaseRecords.length > 0) {
                const { error } = await supabase.from('attendance_logs')
                    .upsert(supabaseRecords, { onConflict: 'student_id,subject_name,session_date,doctor_uid' }
                    );

                if (error) console.error("❌ Supabase Error:", error);
                else console.log(`✅ Supabase Mirroring Done: ${supabaseRecords.length} records`);
            }
        } catch (supaErr) {
            console.error("❌ Supabase Logic Error:", supaErr);
        }

        try {
            const cleanupBatch = db.batch();
            let cleanupCount = 0;
            partsSnap.forEach(docSnap => {
                const p = docSnap.data();
                if (p.uid) {
                    cleanupBatch.set(
                        db.collection('user_registrations').doc(p.uid),
                        { liveState: { status: 'idle', doctorUID: '', joinedAt: null } },
                        { merge: true }
                    );
                    cleanupCount++;
                    if (cleanupCount >= 400) return;
                }
            });
            if (cleanupCount > 0) await cleanupBatch.commit();
            console.log(`🧹 Cleared liveState for ${cleanupCount} students`);
        } catch (e) {
            console.warn('liveState cleanup skipped:', e.message);
        }

        console.log(`✅ Session Closed | Doctor: ${doctorUID} | College: ${sessionCollege} | Students: ${processedCount}`);
        res.status(200).json({
            success: true,
            message: `تم الحفظ بنجاح`,
            processedCount
        });

    } catch (error) {
        console.error("❌ closeSession Error:", error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/registerFaculty', registerFacultyLimiter, verifyAppCheck, async (req, res) => {

    try {
        const { email, password, fullName, gender, role, jobTitle, masterKey, college } = req.body;

        const keysDoc = await db.collection("system_keys").doc("registration_keys").get();
        if (!keysDoc.exists) return res.status(500).json({ error: "المفاتيح غير مهيأة في السيرفر" });

        const serverKeys = keysDoc.data();

        let isValid = false;
        if (role === 'dean' && masterKey === serverKeys.dean_key) isValid = true;
        if (role === 'doctor' && masterKey === serverKeys.doctor_key) isValid = true;

        if (!isValid) {
            return res.status(403).json({ error: "🚫 المفتاح السري (Master Key) غير صحيح!" });
        }

        const VALID_COLLEGES = ["NURS", "ENG", "ART", "MED", "VET", "MEDIA", "ALSUN", "PT", "DENT", "CS", "PHARM", "HS", "BA"];
        const finalCollege = (college && VALID_COLLEGES.includes(college.toUpperCase()))
            ? college.toUpperCase()
            : "NURS";

        let userRecord;
        try {
            userRecord = await admin.auth().createUser({
                email,
                password,
                displayName: fullName,
            });

            await db.collection("faculty_members").doc(userRecord.uid).set({
                fullName,
                gender,
                role,
                jobTitle,
                email,
                college: finalCollege,
                isVerified: false,
                registeredAt: admin.firestore.FieldValue.serverTimestamp()
            });

            console.log(`✅ Faculty Registered (Pending Approval): ${fullName} | College: ${finalCollege}`);
            res.status(200).json({ success: true, message: "تم تسجيل الحساب، بانتظار الموافقة الإدارية" });

        } catch (innerError) {
            if (userRecord && userRecord.uid) {
                console.log(`⚠️ Rolling back... Deleting orphaned faculty user: ${userRecord.uid}`);
                try {
                    await admin.auth().deleteUser(userRecord.uid);
                    console.log("✅ Rollback Successful.");
                } catch (rollbackError) {
                    console.error("💀 CRITICAL: Faculty rollback failed! UID:", userRecord.uid);
                }
            }
            throw innerError;
        }

    } catch (error) {
        console.error("Faculty Reg Error:", error);
        res.status(500).json({ error: error.message });
    }
});

const verifyDeanRole = async (req, res, next) => {
    try {
        const uid = req.user.uid;
        const docSnap = await db.collection("faculty_members").doc(uid).get();

        if (docSnap.exists && docSnap.data().role === 'dean' && docSnap.data().isVerified === true) {
            return next();
        }
        return res.status(403).json({ error: "🚫 الموافقة متاحة فقط لعميد مفعّل" });
    } catch (e) {
        res.status(500).json({ error: "Security Check Failed" });
    }
};

app.post('/api/approveFaculty', verifyToken, verifyDeanRole, verifyAppCheck, async (req, res) => {
    try {
        const { targetUID } = req.body;
        if (!targetUID) return res.status(400).json({ error: "Missing targetUID" });

        const targetRef = db.collection("faculty_members").doc(targetUID);
        const targetSnap = await targetRef.get();

        if (!targetSnap.exists) {
            return res.status(404).json({ error: "الحساب المطلوب غير موجود" });
        }

        const targetData = targetSnap.data();

        if (targetData.isVerified === true) {
            return res.status(400).json({ error: "الحساب مفعّل بالفعل" });
        }

        await admin.auth().setCustomUserClaims(targetUID, {
            adminRole: targetData.role,
            college: targetData.college || 'NURS',
            isAdminDoctor: targetData.isAdminDoctor || false
        });

        await targetRef.update({
            isVerified: true,
            approvedBy: req.user.uid,
            approvedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`✅ Faculty Approved: ${targetData.fullName} by ${req.user.uid}`);
        res.status(200).json({ success: true, message: "تم تفعيل الحساب بنجاح" });

    } catch (error) {
        console.error("Approve Faculty Error:", error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/registerStudent', async (req, res) => {
    let createdUserUID = null;

    try {
        let { email, password, fullName, studentID, level, gender, group, deviceFingerprint } = req.body;

        if (!studentID || !email || !password || !fullName || !level || !gender) {
            return res.status(400).json({ error: "بيانات ناقصة! يرجى ملء جميع الحقول المطلوبة." });
        }

        const cleanID = studentID.toString().trim();
        const cleanEmail = email.toString().trim();
        const cleanName = fullName.toString().trim();

        let finalGroup = "عام";

        if (group && group.trim() !== "") {
            const groupUpper = group.toString().toUpperCase().trim();
            const groupPattern = /^[1-4][NPCDBTH]\d{1,2}$/;

            if (!groupPattern.test(groupUpper)) {
                return res.status(400).json({
                    error: "صيغة الجروب غير صحيحة. مثال: 1N1 (تمريض) أو 1D1 (أسنان) أو 1P1 (علاج طبيعي)"
                });
            }

            if (level && !groupUpper.startsWith(level.toString())) {
                return res.status(400).json({
                    error: `تضارب البيانات: اخترت الفرقة ${level} ولكن الجروب ${groupUpper} يتبع فرقة أخرى!`
                });
            }

            finalGroup = groupUpper;
        }

        const collegeMap = {
            'N': 'NURS', 'P': 'PT', 'C': 'PHARM',
            'D': 'DENT', 'T': 'CS', 'B': 'BA', 'H': 'HS'
        };
        const groupLetter = finalGroup.length >= 2 ? finalGroup[1] : 'N';
        const detectedCollege = collegeMap[groupLetter] || 'NURS';


        const idCheck = await db.collection("taken_student_ids").doc(cleanID).get();
        if (idCheck.exists) {
            return res.status(409).json({ error: "هذا الكود الجامعي مسجل بالفعل!" });
        }

        const userRecord = await admin.auth().createUser({
            email: cleanEmail,
            password: password,
            displayName: cleanName,
            emailVerified: false
        });

        createdUserUID = userRecord.uid;

        const batch = db.batch();

        batch.set(db.collection("taken_student_ids").doc(cleanID), {
            saved_email: cleanEmail,
            saved_name: cleanName,
            saved_uid: createdUserUID,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        batch.set(db.collection("user_registrations").doc(createdUserUID), {
            registrationInfo: {
                fullName: cleanName,
                studentID: cleanID,
                level: level.toString(),
                gender: gender,
                group: finalGroup,
                college: detectedCollege
            },
            role: "student",
            attendanceCount: 0,
            avatarClass: "fa-user-graduate",
            status: "pending_verification",
            accountCreated: admin.firestore.FieldValue.serverTimestamp()
        });

        const safeFP = deviceFingerprint || "UNKNOWN_DEVICE";

        batch.set(db.collection("user_registrations").doc(createdUserUID).collection("sensitive_info").doc("main"), {
            email: cleanEmail,
            bound_device_id: safeFP,
            created_via: "Secure_Backend_V3"
        });

        await batch.commit();
        createdUserUID = null;

        res.status(200).json({ success: true, uid: userRecord.uid });

    } catch (error) {
        console.error("❌ Registration Failed:", error);

        if (createdUserUID) {
            console.log(`⚠️ Rolling back... Deleting orphaned user: ${createdUserUID}`);
            try {
                await admin.auth().deleteUser(createdUserUID);
                console.log("✅ Rollback Successful.");
            } catch (rollbackError) {
                console.error("💀 CRITICAL: Rollback failed! UID:", createdUserUID);
            }
        }

        if (error.code === 'auth/email-already-in-use') {
            return res.status(409).json({ error: "البريد الإلكتروني مستخدم بالفعل" });
        }
        if (error.code === 'auth/invalid-email') {
            return res.status(400).json({ error: "صيغة البريد الإلكتروني غير صحيحة" });
        }
        if (error.code === 'auth/weak-password') {
            return res.status(400).json({ error: "كلمة المرور ضعيفة جداً" });
        }

        res.status(500).json({ error: "فشل التسجيل: " + error.message });
    }
});

app.get('/api/config', (req, res) => {
    res.json({
        authDomain: "attendance-system-pro-dbdf1.firebaseapp.com",
        projectId: "attendance-system-pro-dbdf1",
        messagingSenderId: "1094544109334",
        appId: "1:1094544109334:web:a7395159d617b3e6e82a37"
    });
});

const PORT = process.env.PORT || 3000;


app.post('/api/get-theory-day', verifyToken, async (req, res) => {
    try {
        const { subject, doctorUID, date } = req.body;

        if (req.user.uid !== doctorUID) {
            return res.status(403).json({ error: "غير مصرح لك بسحب هذا التقرير" });
        }
        if (!subject || !doctorUID || !date) {
            return res.status(400).json({ error: "بيانات البحث ناقصة" });
        }

        const { data: todayLogs, error: todayError } = await supabase
            .from('attendance_logs')
            .select('student_id, student_name, target_group, status, attendance_time, is_unruly, is_uniform_violation')
            .eq('subject_name', subject)
            .eq('doctor_uid', doctorUID)
            .eq('session_date', date);

        if (todayError) throw todayError;

        const { data: absenceLogs, error: absenceError } = await supabase
            .from('attendance_logs')
            .select('student_id')
            .eq('subject_name', subject)
            .eq('doctor_uid', doctorUID)
            .eq('status', 'ABSENT');

        if (absenceError) throw absenceError;

        res.status(200).json({ todayLogs: todayLogs || [], absenceLogs: absenceLogs || [] });

    } catch (err) {
        console.error("Theory Day Route Error:", err.message);
        res.status(500).json({ error: "فشل استخراج التقرير من قاعدة البيانات" });
    }
});
app.post('/api/sync-supabase', verifyToken, verifyStaffRole, async (req, res) => {

    try {
        const { attended, absent, meta, doctorUID } = req.body;
        const records = [];

        if (req.user.uid !== doctorUID) {
            return res.status(403).json({ error: "غير مصرح لك بإرسال بيانات دكتور آخر" });
        }

        (attended || []).forEach(p => {
            records.push({
                student_id: p.id, student_name: p.name, subject_name: meta.rawSubject,
                college: meta.college || "NURS", hall: meta.hall || "",
                target_group: p.group || (meta.targetGroups && meta.targetGroups[0]) || "General",
                sis_code: meta.sisCode || "", session_date: meta.fixedDateStr,
                attendance_time: p.time_str || meta.closeTimeStr,
                status: "ATTENDED", is_unruly: p.isUnruly || false,
                is_uniform_violation: p.isUniformViolation || false,
                notes: p.isUnruly ? "غير منضبط - مشاغب" : (p.isUniformViolation ? "مخالفة زي" : "منضبط"),
                doctor_uid: doctorUID, doctor_name: meta.doctorName, is_recovered: false,
                feedback_status: "pending",
                feedback_rating: 0,
                segment_count: p.segment_count || 1,
                is_offline_sync: false,
                group_name: p.group || (meta.targetGroups && meta.targetGroups[0]) || "General",
                level: p.level || "-",
                is_suspicious: p.isSuspicious || false,
                trap_is_in_range: p.trap_report?.is_in_range ?? null,
                trap_is_device_match: p.trap_report?.is_device_match ?? null,
                trap_gps_success: p.trap_report?.gps_success ?? null,
                trap_distance_km: p.trap_report?.distance_km ?? null,
            });
        });

        (absent || []).forEach(s => {
            records.push({
                student_id: s.id, student_name: s.name, subject_name: meta.rawSubject,
                college: meta.college || "NURS", hall: meta.hall || "", target_group: s.group || (meta.targetGroups && meta.targetGroups[0]) || "General",
                sis_code: meta.sisCode || "", session_date: meta.fixedDateStr, attendance_time: "--:--",
                status: "ABSENT", is_unruly: false, is_uniform_violation: false, notes: "غائب",
                doctor_uid: doctorUID, doctor_name: meta.doctorName, is_recovered: false
            });
        });

        if (records.length > 0) {
            const { error } = await supabase.from('attendance_logs').upsert(records, { onConflict: 'student_id,subject_name,session_date,doctor_uid' }

            );
            if (error) throw error;
        }
        res.status(200).json({ success: true, count: records.length });
    } catch (err) {
        console.error("Sync Route Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});


app.post('/api/get-archive', verifyToken, async (req, res) => {
    try {
        const { subject, doctorUID, startDate, endDate } = req.body;

        if (req.user.uid !== doctorUID) {
            return res.status(403).json({ error: "غير مصرح لك بسحب هذا التقرير" });
        }

        if (!subject || !doctorUID || !startDate || !endDate) {
            return res.status(400).json({ error: "بيانات البحث ناقصة" });
        }

        const { data: logs, error } = await supabase
            .from('attendance_logs')
            .select('student_id, student_name, target_group, session_date, status')
            .eq('subject_name', subject)
            .eq('doctor_uid', doctorUID);

        if (error) throw error;

        const startObj = new Date(startDate);
        const endObj = new Date(endDate);
        endObj.setHours(23, 59, 59, 999);

        const filteredLogs = logs.filter(log => {
            const [d, m, y] = log.session_date.split('/');
            const logDate = new Date(`${y}-${m}-${d}`);
            return logDate >= startObj && logDate <= endObj;
        });

        const lecturesSet = new Set();
        const studentsMap = new Map();

        filteredLogs.forEach(log => {
            if (log.status !== "ABSENT") lecturesSet.add(log.session_date);
        });

        const lectures = Array.from(lecturesSet).sort((a, b) => {
            const [d1, m1, y1] = a.split('/');
            const [d2, m2, y2] = b.split('/');
            return new Date(`${y1}-${m1}-${d1}`) - new Date(`${y2}-${m2}-${d2}`);
        });

        filteredLogs.forEach(log => {
            if (!studentsMap.has(log.student_id)) {
                studentsMap.set(log.student_id, {
                    id: log.student_id,
                    name: log.student_name,
                    group: log.target_group,
                    attendance: {}
                });
            }

            const student = studentsMap.get(log.student_id);
            if (log.status !== "ABSENT") {
                student.attendance[log.session_date] = "P";
            } else if (!student.attendance[log.session_date]) {
                student.attendance[log.session_date] = "A";
            }
        });

        studentsMap.forEach(student => {
            lectures.forEach(date => {
                if (!student.attendance[date]) student.attendance[date] = "A";
            });
        });

        const students = Array.from(studentsMap.values()).sort((a, b) =>
            String(a.id).localeCompare(String(b.id), undefined, { numeric: true, sensitivity: 'base' })
        );

        res.status(200).json({ lectures, students });

    } catch (err) {
        console.error("Archive Route Error:", err.message);
        res.status(500).json({ error: "فشل استخراج التقرير من قاعدة البيانات" });
    }
});
app.listen(PORT, () => console.log(`🛡️ Server Running Port ${PORT}`));

module.exports = app;
