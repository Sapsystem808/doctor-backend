
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

async function setDoctorClaims(uid, college, isAdmin = false, role = 'doctor') {
    await admin.auth().setCustomUserClaims(uid, {
        role: role,
        college: college || 'NURS',
        isAdminDoctor: isAdmin
    });
}

async function setStudentClaims(uid, college, studentId) {
    await admin.auth().setCustomUserClaims(uid, {
        role: 'student',
        college: college || 'NURS',
        studentId: String(studentId)
    });
}

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
    "https://smart-attendance-pro-sap.web.app",
    "https://smart-attendance-pro-sap.firebaseapp.com",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501"
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
        const { role, college } = req.user;
        if ((role === 'doctor' || role === 'dean') && college) {
            req.staffData = { role, college };
            return next();
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


app.post('/api/registerFaculty', registerFacultyLimiter, async (req, res) => {

    try {
        const { email, password, fullName, gender, role, jobTitle, masterKey, college } = req.body;

        if (!email || !password || !fullName || !gender || !role || !jobTitle || !masterKey) {
            return res.status(400).json({ error: "بيانات ناقصة! يرجى ملء جميع الحقول المطلوبة." });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email.trim())) {
            return res.status(400).json({ error: "صيغة البريد الإلكتروني غير صحيحة" });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ error: "كلمة المرور ضعيفة! يجب أن تكون 8 أحرف على الأقل وتحتوي على حرف كبير وصغير ورقم" });
        }

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

            const facRef = db.collection("faculty_members").doc(userRecord.uid);
            const batch = db.batch();

            batch.set(facRef, {
                fullName,
                gender,
                role,
                jobTitle,
                college: finalCollege,
                isVerified: false,
                registeredAt: admin.firestore.FieldValue.serverTimestamp()
            });

            batch.set(facRef.collection("sensitive_info").doc("main"), {
                email,
                created_via: "Secure_Backend_Faculty"
            });

            await batch.commit();
            await setDoctorClaims(userRecord.uid, finalCollege, false, role);
            console.log(`✅ Faculty Registered + Claims Set: ${fullName} | College: ${finalCollege}`);
            res.status(200).json({ success: true, message: "تم تسجيل الحساب وتفعيله بنجاح ✅" });

        } catch (innerError) {
            if (userRecord && userRecord.uid) {
                console.log(`⚠️ Rolling back... Deleting orphaned faculty user: ${userRecord.uid}`);
                try {
                    await admin.auth().deleteUser(userRecord.uid);
                } catch (rollbackError) {
                    console.error("💀 CRITICAL: Faculty rollback failed! UID:", userRecord.uid);
                }
                try {
                    await db.collection("faculty_members").doc(userRecord.uid).delete();
                    await db.collection("faculty_members").doc(userRecord.uid).collection("sensitive_info").doc("main").delete();
                    console.log("✅ Rollback Successful (Auth + Firestore).");
                } catch (cleanupErr) {
                    console.error("💀 CRITICAL: Faculty Firestore cleanup failed! UID:", userRecord.uid);
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
        const { role, college } = req.user;
        if (role === 'dean' && college) {
            return next();
        }
        return res.status(403).json({ error: "🚫 الموافقة متاحة فقط لعميد مفعّل" });
    } catch (e) {
        res.status(500).json({ error: "Security Check Failed" });
    }
};

app.post('/api/approveFaculty', verifyToken, verifyDeanRole, async (req, res) => {
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

        await setDoctorClaims(
            targetUID,
            targetData.college || 'NURS',
            targetData.isAdminDoctor || false,
            targetData.role
        );

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
        const { attended, absent, left, meta, doctorUID } = req.body;
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
        (left || []).forEach(s => {
            records.push({
                student_id: s.id, student_name: s.name, subject_name: meta.rawSubject,
                college: meta.college || "NURS", hall: meta.hall || "",
                target_group: s.group || (meta.targetGroups && meta.targetGroups[0]) || "General",
                sis_code: meta.sisCode || "", session_date: meta.fixedDateStr,
                attendance_time: meta.closeTimeStr || "--:--",
                status: "LEFT", is_unruly: false, is_uniform_violation: false,
                notes: "غادر أثناء الاستراحة",
                doctor_uid: doctorUID, doctor_name: meta.doctorName,
                is_recovered: false, segment_count: s.segment_count || 1
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
        const { subject, doctorUID, doctorCollege, startDate, endDate } = req.body;

        if (req.user.uid !== doctorUID) {
            return res.status(403).json({ error: "غير مصرح لك بسحب هذا التقرير" });
        }

        if (!subject || !doctorUID || !startDate || !endDate) {
            return res.status(400).json({ error: "بيانات البحث ناقصة" });
        }

        const enrollmentsRef = db.collection('subject_enrollments');
        const [ownSnap, sharedSnap] = await Promise.all([
            enrollmentsRef.where('doctorUID', '==', doctorUID).where('subjectName', '==', subject).get(),
            enrollmentsRef.where('sharedWithAll', '==', true).where('subjectName', '==', subject).where('college', '==', doctorCollege || "NURS").get()
        ]);

        let enrollmentDocIds = [];
        if (!ownSnap.empty) {
            ownSnap.forEach(d => enrollmentDocIds.push(d.id));
        } else if (!sharedSnap.empty) {
            sharedSnap.forEach(d => enrollmentDocIds.push(d.id));
        }

        let masterStudents = [];
        if (enrollmentDocIds.length > 0) {
            const rostersPromises = enrollmentDocIds.map(id => db.collection('subject_rosters').doc(id).get());
            const rostersSnaps = await Promise.all(rostersPromises);
            rostersSnaps.forEach(rosterSnap => {
                if (rosterSnap.exists) {
                    const data = rosterSnap.data();
                    if (Array.isArray(data.students)) {
                        masterStudents.push(...data.students);
                    }
                }
            });
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

        masterStudents.forEach(s => {
            studentsMap.set(String(s.id).trim(), {
                id: String(s.id).trim(),
                name: s.name,
                group: s.group || '--',
                attendance: {}
            });
        });


        filteredLogs.forEach(log => {
            lecturesSet.add(log.session_date);
        });

        const lectures = Array.from(lecturesSet).sort((a, b) => {
            const [d1, m1, y1] = a.split('/');
            const [d2, m2, y2] = b.split('/');
            return new Date(`${y1}-${m1}-${d1}`) - new Date(`${y2}-${m2}-${d2}`);
        });

        filteredLogs.forEach(log => {
            const sId = String(log.student_id).trim();

            if (!studentsMap.has(sId)) {
                studentsMap.set(sId, {
                    id: sId,
                    name: log.student_name,
                    group: log.target_group || '--',
                    attendance: {}
                });
            }

            const student = studentsMap.get(sId);

            if (log.status === "ATTENDED") {
                student.attendance[log.session_date] = "P";
            } else if (log.status === "LEFT") {
                if (student.attendance[log.session_date] !== "P") {
                    student.attendance[log.session_date] = "L";
                }
            } else if (log.status === "ABSENT") {
                if (!student.attendance[log.session_date]) {
                    student.attendance[log.session_date] = "A";
                }
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

const MANUAL_ADD_DAILY_LIMIT = 20;

// تاريخ اليوم بتوقيت القاهرة، محسوب من السيرفر مش من الكلاينت
function getServerDateKey() {
    return new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' }); // YYYY-MM-DD
}

// نفس منطق البحث اللي كان في الفرونت إند، منقول بالكامل هنا
async function findStudentByCode(codeString) {
    const [directDoc, byIdField, byUserReg, uidSnap] = await Promise.all([
        db.collection("students").doc(codeString).get(),
        db.collection("students").where("id", "==", codeString).limit(1).get(),
        db.collection("user_registrations").where("registrationInfo.studentID", "==", codeString).limit(1).get(),
        db.collection("taken_student_ids").doc(codeString).get()
    ]);

    let sData = null;
    let finalUID = codeString;

    if (!byUserReg.empty) {
        const userData = byUserReg.docs[0].data();
        sData = userData.registrationInfo || userData;
        finalUID = byUserReg.docs[0].id;
    } else if (directDoc.exists) {
        sData = directDoc.data();
    } else if (!byIdField.empty) {
        sData = byIdField.docs[0].data();
    }

    if (!sData) return null;
    if (uidSnap.exists) finalUID = uidSnap.data().saved_uid || finalUID;

    return {
        uid: String(finalUID),
        code: String(codeString),
        name: String(sData.name || sData.fullName || "Student")
    };
}

app.post('/api/session/searchManualStudent', verifyToken, verifyStaffRole, async (req, res) => {
    try {
        const code = String(req.body.code || '').trim();
        if (!code) return res.status(400).json({ error: "⚠️ يرجى كتابة كود الطالب أولاً" });

        const student = await findStudentByCode(code);
        if (!student) return res.status(404).json({ error: "❌ الكود غير مسجل في قاعدة البيانات" });

        res.status(200).json({ success: true, name: student.name, code: student.code, uid: student.uid });
    } catch (err) {
        console.error("Manual Search Error:", err.message);
        res.status(500).json({ error: "⚠️ حدث خطأ أثناء البحث" });
    }
});

app.post('/api/session/confirmManualAdd', verifyToken, verifyStaffRole, async (req, res) => {
    try {
        const doctorUID = req.user.uid;
        const code = String(req.body.code || '').trim();
        const uid = String(req.body.uid || '').trim();
        const name = String(req.body.name || '').trim();

        if (!code || !uid || !name) {
            return res.status(400).json({ error: "⚠️ بيانات ناقصة، أعد البحث من جديد" });
        }

        const sessionRef = db.collection("active_sessions").doc(doctorUID);
        const dateKey = getServerDateKey();
        const limitRef = db.collection("manual_add_limits").doc(`${doctorUID}_${dateKey}`);
        const participantRef = sessionRef.collection("participants").doc(uid);

        const result = await db.runTransaction(async (tx) => {
            // 1. قراءة كل المستندات في نفس اللحظة داخل الـ Transaction (أمان وعزل تام)
            const [sessionSnap, limitSnap, participantSnap] = await Promise.all([
                tx.get(sessionRef),
                tx.get(limitRef),
                tx.get(participantRef)
            ]);

            // 2. التحقق من حالة الجلسة
            if (!sessionSnap.exists || sessionSnap.data().isActive !== true) {
                return { sessionClosed: true };
            }
            const sessionData = sessionSnap.data();

            // 3. التحقق من تواجد الطالب مسبقاً
            if (participantSnap.exists && ["active", "on_break"].includes(participantSnap.data().status)) {
                return { alreadyExists: true };
            }

            // 4. التحقق من الحد الأقصى من الكوليكشن المنفصل الخاص بك
            const currentCount = limitSnap.exists ? (limitSnap.data().count || 0) : 0;
            if (currentCount >= MANUAL_ADD_DAILY_LIMIT) {
                return { limitReached: true };
            }

            // 5. التنفيذ: تحديث عداد الحد الأقصى في مكانه المنفصل
            tx.set(limitRef, {
                doctorUID,
                date: dateKey,
                count: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });

            // 6. إضافة الطالب للجلسة
            tx.set(participantRef, {
                id: code,
                uid: uid,
                name: name,
                status: "active",
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                method: "Manual_By_Prof",
                isUnruly: false,
                isUniformViolation: false,
                avatarClass: "fa-user-check",
                segment_count: 1,
                subject: sessionData.allowedSubject || "Manual Add",
                hall: sessionData.hall || "Manual",
                doctorName: sessionData.doctorName || "",
                addedByUID: doctorUID,
                time_str: new Date().toLocaleTimeString("ar-EG", { hour: "2-digit", minute: "2-digit", timeZone: "Africa/Cairo" })
            });

            return { success: true, newCount: currentCount + 1 };
        });

        // التعامل مع الردود
        if (result.sessionClosed) {
            return res.status(400).json({ error: "🔒 لا توجد جلسة نشطة حالياً" });
        }
        if (result.alreadyExists) {
            return res.status(409).json({ error: `⚠️ الطالب "${name}" موجود بالفعل` });
        }
        if (result.limitReached) {
            return res.status(429).json({ error: `🚫 وصلت للحد الأقصى (${MANUAL_ADD_DAILY_LIMIT} طالب يدوي) لهذا اليوم` });
        }

        res.status(200).json({ success: true, name: name, count: result.newCount, limit: MANUAL_ADD_DAILY_LIMIT });
    } catch (err) {
        console.error("Manual Add Confirm Error:", err.message);
        res.status(500).json({ error: "❌ فشل الحفظ، حاول مجدداً" });
    }
});

app.listen(PORT, () => console.log(`🛡️ Server Running Port ${PORT}`));

module.exports = app;