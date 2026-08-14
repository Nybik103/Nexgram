const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true
    },
    maxHttpBufferSize: 2 * 1024 * 1024
});

const PORT = Number(process.env.PORT) || 3000;
const SESSION_COOKIE = "nexgram_session";
const SESSION_DAYS = 30;

const isProduction =
    process.env.NODE_ENV === "production";


/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: false,
    limit: "2mb"
}));

app.use(cookieParser());

app.use(express.static(
    path.join(__dirname, "public")
));


/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
    path.join(__dirname, "messenger.db")
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");


/*
    USERS

    Старые пользователи сохранятся.
    Новые поля добавляются автоматически.
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT DEFAULT '',
        about TEXT DEFAULT '',
        avatar TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);


/*
    Добавляем недостающие поля,
    если база была создана старой версией.
*/

function addColumnIfMissing(
    table,
    column,
    definition
) {

    const columns =
        db.prepare(
            `PRAGMA table_info(${table})`
        ).all();

    const exists =
        columns.some(
            item => item.name === column
        );

    if (!exists) {

        db.exec(
            `ALTER TABLE ${table}
             ADD COLUMN ${column} ${definition}`
        );
    }
}


addColumnIfMissing(
    "users",
    "display_name",
    "TEXT DEFAULT ''"
);

addColumnIfMissing(
    "users",
    "about",
    "TEXT DEFAULT ''"
);

addColumnIfMissing(
    "users",
    "avatar",
    "TEXT DEFAULT ''"
);

addColumnIfMissing(
    "users",
    "created_at",
    "DATETIME DEFAULT CURRENT_TIMESTAMP"
);


/*
    MESSAGES
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        text TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

addColumnIfMissing(
    "messages",
    "is_read",
    "INTEGER DEFAULT 0"
);


/*
    SESSIONS

    Сессия хранится на сервере.
    В cookie находится только случайный токен.
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    )
`);


/*
    Индексы
*/

db.exec(`
    CREATE INDEX IF NOT EXISTS
    idx_users_username
    ON users(username);

    CREATE INDEX IF NOT EXISTS
    idx_sessions_token
    ON sessions(token_hash);

    CREATE INDEX IF NOT EXISTS
    idx_sessions_expiry
    ON sessions(expires_at);

    CREATE INDEX IF NOT EXISTS
    idx_messages_conversation
    ON messages(sender, recipient);

    CREATE INDEX IF NOT EXISTS
    idx_messages_recipient_read
    ON messages(recipient, is_read);
`);


console.log("База данных Nexgram подключена.");


/* =========================================================
   PASSWORD HASHING
========================================================= */

/*
    Используем scrypt вместо простого SHA-256.

    Формат:
    scrypt$N$r$p$salt$hash
*/

function hashPassword(password) {

    const salt =
        crypto.randomBytes(16).toString("hex");

    const N = 16384;
    const r = 8;
    const p = 1;

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64,
            {
                N,
                r,
                p
            }
        ).toString("hex");

    return [
        "scrypt",
        N,
        r,
        p,
        salt,
        hash
    ].join("$");
}


function verifyPassword(
    password,
    stored
) {

    try {

        const parts =
            stored.split("$");

        if (
            parts.length !== 6 ||
            parts[0] !== "scrypt"
        ) {
            return false;
        }

        const N =
            Number(parts[1]);

        const r =
            Number(parts[2]);

        const p =
            Number(parts[3]);

        const salt =
            parts[4];

        const originalHash =
            parts[5];

        const calculated =
            crypto.scryptSync(
                password,
                salt,
                64,
                {
                    N,
                    r,
                    p
                }
            ).toString("hex");

        const a =
            Buffer.from(
                calculated,
                "hex"
            );

        const b =
            Buffer.from(
                originalHash,
                "hex"
            );

        if (a.length !== b.length) {
            return false;
        }

        return crypto.timingSafeEqual(
            a,
            b
        );

    } catch {

        return false;

    }

}


/* =========================================================
   VALIDATION
========================================================= */

function normalizeUsername(value) {

    return String(value || "")
        .trim()
        .replace(/^@+/, "")
        .toLowerCase();

}


function validUsername(username) {

    return /^[a-zA-Z0-9]{5,20}$/
        .test(username);

}


function cleanText(
    value,
    maxLength
) {

    return String(value || "")
        .trim()
        .slice(0, maxLength);

}


function isValidAvatar(
    avatar
) {

    if (!avatar) {
        return true;
    }

    /*
        Разрешаем data:image/...,
        которые использует твой текущий index.html.
    */

    if (
        !avatar.startsWith(
            "data:image/"
        )
    ) {

        return false;

    }

    /*
        Не больше примерно 1.5 MB
        уже после Base64.
    */

    if (
        Buffer.byteLength(
            avatar,
            "utf8"
        ) > 1.5 * 1024 * 1024
    ) {

        return false;

    }

    return true;

}


/* =========================================================
   SESSION HELPERS
========================================================= */

function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


function createSession(
    userId
) {

    const token =
        crypto.randomBytes(48)
            .toString("hex");

    const tokenHash =
        hashToken(token);

    const expiresAt =
        Date.now() +
        SESSION_DAYS *
        24 *
        60 *
        60 *
        1000;


    db.prepare(`
        INSERT INTO sessions
        (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
    `).run(
        userId,
        tokenHash,
        expiresAt
    );


    return {
        token,
        expiresAt
    };

}


function deleteSession(
    token
) {

    if (!token) {
        return;
    }

    db.prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
    `).run(
        hashToken(token)
    );

}


function getUserBySession(
    token
) {

    if (!token) {
        return null;
    }

    const row =
        db.prepare(`
            SELECT
                u.id,
                u.username,
                u.display_name,
                u.about,
                u.avatar
            FROM sessions s
            JOIN users u
                ON u.id = s.user_id
            WHERE
                s.token_hash = ?
                AND s.expires_at > ?
        `).get(
            hashToken(token),
            Date.now()
        );

    return row || null;

}


/*
    Устанавливаем cookie.
*/

function setSessionCookie(
    res,
    token
) {

    res.cookie(
        SESSION_COOKIE,
        token,
        {
            httpOnly: true,
            sameSite: "lax",
            secure: isProduction,
            maxAge:
                SESSION_DAYS *
                24 *
                60 *
                60 *
                1000,
            path: "/"
        }
    );

}


function clearSessionCookie(
    res
) {

    res.clearCookie(
        SESSION_COOKIE,
        {
            httpOnly: true,
            sameSite: "lax",
            secure: isProduction,
            path: "/"
        }
    );

}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(
    req,
    res,
    next
) {

    const token =
        req.cookies[
            SESSION_COOKIE
        ];

    const user =
        getUserBySession(token);

    if (!user) {

        return res.status(401).json({
            error: "Не авторизован."
        });

    }

    req.user = user;

    next();

}


/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

function cleanExpiredSessions() {

    db.prepare(`
        DELETE FROM sessions
        WHERE expires_at <= ?
    `).run(
        Date.now()
    );

}

setInterval(
    cleanExpiredSessions,
    60 * 60 * 1000
);


/* =========================================================
   ONLINE USERS
========================================================= */

/*
    username -> Set(socket.id)
*/

const onlineUsers =
    new Map();


function setOnline(
    username,
    socketId
) {

    if (!onlineUsers.has(username)) {

        onlineUsers.set(
            username,
            new Set()
        );

    }

    onlineUsers
        .get(username)
        .add(socketId);

}


function setOffline(
    username,
    socketId
) {

    const sockets =
        onlineUsers.get(username);

    if (!sockets) {
        return;
    }

    sockets.delete(socketId);

    if (sockets.size === 0) {

        onlineUsers.delete(
            username
        );

    }

}


function isOnline(
    username
) {

    return onlineUsers.has(
        username
    );

}


function emitOnlineStatus(
    username,
    online
) {

    io.emit(
        "user online status",
        {
            username,
            online
        }
    );

}


/* =========================================================
   USER PROFILE
========================================================= */

function getProfile(
    username
) {

    return db.prepare(`
        SELECT
            username,
            display_name,
            about,
            avatar
        FROM users
        WHERE username = ?
    `).get(username);

}


/* =========================================================
   CHAT LIST
========================================================= */

function getChats(
    username
) {

    const rows =
        db.prepare(`
            SELECT
                CASE
                    WHEN sender = ?
                    THEN recipient
                    ELSE sender
                END AS other_username,

                text,
                created_at

            FROM messages

            WHERE
                sender = ?
                OR recipient = ?

            ORDER BY id DESC
        `).all(
            username,
            username,
            username
        );


    const result = [];
    const seen = new Set();


    for (
        const row of rows
    ) {

        if (
            seen.has(
                row.other_username
            )
        ) {
            continue;
        }

        seen.add(
            row.other_username
        );


        const profile =
            getProfile(
                row.other_username
            );

        if (!profile) {
            continue;
        }


        result.push({
            username:
                profile.username,

            display_name:
                profile.display_name,

            about:
                profile.about,

            avatar:
                profile.avatar,

            lastMessage:
                row.text,

            lastMessageAt:
                row.created_at
        });

    }


    return result;

}


/* =========================================================
   HTTP AUTH ROUTES
========================================================= */

/*
    Проверка текущей сессии.
*/

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        res.json({
            user: req.user
        });

    }
);


/*
    Выход.
*/

app.post(
    "/api/logout",
    (req, res) => {

        const token =
            req.cookies[
                SESSION_COOKIE
            ];

        deleteSession(token);

        clearSessionCookie(res);

        res.json({
            success: true
        });

    }
);


/* =========================================================
   SOCKET.IO
========================================================= */

io.on(
    "connection",
    socket => {

        console.log(
            "Socket подключён:",
            socket.id
        );


        /*
            Если cookie уже существует,
            восстанавливаем авторизацию.
        */

        const cookieHeader =
            socket.handshake.headers.cookie ||
            "";

        let sessionToken = null;

        cookieHeader
            .split(";")
            .forEach(part => {

                const [key, ...rest] =
                    part.trim().split("=");

                if (
                    key === SESSION_COOKIE
                ) {

                    sessionToken =
                        decodeURIComponent(
                            rest.join("=")
                        );

                }

            });


        const sessionUser =
            getUserBySession(
                sessionToken
            );


        if (sessionUser) {

            socket.data.user =
                sessionUser;

            socket.data.sessionToken =
                sessionToken;

            setOnline(
                sessionUser.username,
                socket.id
            );

            emitOnlineStatus(
                sessionUser.username,
                true
            );


            /*
                Позволяет старому index.html
                продолжить работу после обновления страницы.
            */

            socket.emit(
                "auth success",
                sessionUser.username
            );

        }


        /* =====================================================
           РЕГИСТРАЦИЯ
        ===================================================== */

        socket.on(
            "register account",
            data => {

                try {

                    const username =
                        normalizeUsername(
                            data?.username
                        );

                    const password =
                        String(
                            data?.password || ""
                        );

                    const displayName =
                        cleanText(
                            data?.displayName,
                            40
                        );


                    if (
                        !validUsername(
                            username
                        )
                    ) {

                        socket.emit(
                            "auth error",
                            "Юзернейм должен содержать от 5 до 20 символов и только английские буквы и цифры."
                        );

                        return;

                    }


                    if (
                        password.length < 8
                    ) {

                        socket.emit(
                            "auth error",
                            "Пароль должен содержать минимум 8 символов."
                        );

                        return;

                    }


                    if (!displayName) {

                        socket.emit(
                            "auth error",
                            "Введите ваше имя."
                        );

                        return;

                    }


                    const existing =
                        db.prepare(`
                            SELECT id
                            FROM users
                            WHERE username = ?
                        `).get(
                            username
                        );


                    if (existing) {

                        socket.emit(
                            "auth error",
                            "Такой username уже занят."
                        );

                        return;

                    }


                    const passwordHash =
                        hashPassword(
                            password
                        );


                    const result =
                        db.prepare(`
                            INSERT INTO users
                            (
                                username,
                                password,
                                display_name,
                                about,
                                avatar
                            )
                            VALUES (?, ?, ?, '', '')
                        `).run(
                            username,
                            passwordHash,
                            displayName
                        );


                    const userId =
                        Number(
                            result.lastInsertRowid
                        );


                    const session =
                        createSession(
                            userId
                        );


                    /*
                        Socket.IO не может сам
                        поставить HTTP cookie после
                        установления соединения,
                        поэтому отправляем токен
                        клиенту для установки cookie
                        через HTTP.
                    */

                    socket.data.user =
                        getProfile(
                            username
                        );

                    socket.data.user.id =
                        userId;

                    socket.data.sessionToken =
                        session.token;


                    /*
                        Для текущего клиента
                        также отправляем событие.
                    */

                    socket.emit(
                        "auth success",
                        username
                    );


                    /*
                        Выдаём токен событием.
                        Новый index.html сможет
                        сохранить его через
                        /api/session.
                    */

                    socket.emit(
                        "session created",
                        {
                            token:
                                session.token
                        }
                    );

                } catch (error) {

                    console.error(
                        "Ошибка регистрации:",
                        error
                    );

                    socket.emit(
                        "auth error",
                        "Не удалось создать аккаунт."
                    );

                }

            }
        );


        /* =====================================================
           ВХОД
        ===================================================== */

        socket.on(
            "login account",
            data => {

                try {

                    const username =
                        normalizeUsername(
                            data?.username
                        );

                    const password =
                        String(
                            data?.password || ""
                        );


                    if (
                        !validUsername(
                            username
                        )
                    ) {

                        socket.emit(
                            "auth error",
                            "Некорректный username."
                        );

                        return;

                    }


                    const user =
                        db.prepare(`
                            SELECT
                                id,
                                username,
                                password,
                                display_name,
                                about,
                                avatar
                            FROM users
                            WHERE username = ?
                        `).get(
                            username
                        );


                    if (!user) {

                        socket.emit(
                            "auth error",
                            "Пользователь не найден."
                        );

                        return;

                    }


                    if (
                        !verifyPassword(
                            password,
                            user.password
                        )
                    ) {

                        socket.emit(
                            "auth error",
                            "Неверный пароль."
                        );

                        return;

                    }


                    const session =
                        createSession(
                            user.id
                        );


                    socket.data.user =
                        {
                            id:
                                user.id,

                            username:
                                user.username,

                            display_name:
                                user.display_name,

                            about:
                                user.about,

                            avatar:
                                user.avatar
                        };


                    socket.data.sessionToken =
                        session.token;


                    socket.emit(
                        "auth success",
                        user.username
                    );


                    socket.emit(
                        "session created",
                        {
                            token:
                                session.token
                        }
                    );

                } catch (error) {

                    console.error(
                        "Ошибка входа:",
                        error
                    );

                    socket.emit(
                        "auth error",
                        "Не удалось выполнить вход."
                    );

                }

            }
        );


        /* =====================================================
           УСТАНОВКА СЕССИИ
        ===================================================== */

        socket.on(
            "set session",
            data => {

                const token =
                    String(
                        data?.token || ""
                    );

                const user =
                    getUserBySession(
                        token
                    );

                if (!user) {

                    socket.emit(
                        "session error",
                        "Сессия недействительна."
                    );

                    return;

                }


                socket.data.user =
                    user;

                socket.data.sessionToken =
                    token;


                setOnline(
                    user.username,
                    socket.id
                );


                emitOnlineStatus(
                    user.username,
                    true
                );

            }
        );


        /* =====================================================
           REGISTER / ONLINE
        ===================================================== */

        socket.on(
            "register",
            username => {

                const user =
                    socket.data.user;

                if (!user) {

                    socket.emit(
                        "auth error",
                        "Сначала войдите в аккаунт."
                    );

                    return;

                }


                /*
                    Игнорируем username,
                    который прислал клиент.

                    Используем только имя
                    из серверной сессии.
                */

                socket.data.user =
                    getProfile(
                        user.username
                    );


                setOnline(
                    user.username,
                    socket.id
                );


                socket.emit(
                    "registered",
                    user.username
                );


                emitOnlineStatus(
                    user.username,
                    true
                );


                socket.emit(
                    "profile",
                    getProfile(
                        user.username
                    )
                );


                socket.emit(
                    "chats",
                    getChats(
                        user.username
                    )
                );

            }
        );


        /* =====================================================
           REQUEST CHATS
        ===================================================== */

        socket.on(
            "request chats",
            () => {

                const user =
                    socket.data.user;

                if (!user) {
                    return;
                }

                socket.emit(
                    "chats",
                    getChats(
                        user.username
                    )
                );

            }
        );


        /* =====================================================
           GET PROFILE
        ===================================================== */

        socket.on(
            "get profile",
            () => {

                const user =
                    socket.data.user;

                if (!user) {
                    return;
                }


                const profile =
                    getProfile(
                        user.username
                    );

                socket.emit(
                    "profile",
                    profile
                );

            }
        );


        /* =====================================================
           SEARCH USERS
        ===================================================== */

        socket.on(
            "search users",
            data => {

                const user =
                    socket.data.user;

                if (!user) {
                    return;
                }


                let query =
                    normalizeUsername(
                        data?.query
                    );


                if (!query) {

                    socket.emit(
                        "search results",
                        []
                    );

                    return;

                }


                query =
                    query.slice(
                        0,
                        20
                    );


                const results =
                    db.prepare(`
                        SELECT
                            username,
                            display_name,
                            about,
                            avatar
                        FROM users
                        WHERE
                            username LIKE ?
                            AND username != ?
                        ORDER BY username
                        LIMIT 20
                    `).all(
                        `%${query}%`,
                        user.username
                    );


                socket.emit(
                    "search results",
                    results
                );

            }
        );


        /* =====================================================
           UPDATE PROFILE
        ===================================================== */

        socket.on(
            "update profile",
            data => {

                const currentUser =
                    socket.data.user;

                if (!currentUser) {

                    socket.emit(
                        "profile error",
                        "Сначала войдите в аккаунт."
                    );

                    return;

                }


                const displayName =
                    cleanText(
                        data?.displayName,
                        40
                    );

                const username =
                    normalizeUsername(
                        data?.username
                    );

                const about =
                    cleanText(
                        data?.about,
                        150
                    );

                const avatar =
                    String(
                        data?.avatar || ""
                    );


                if (!displayName) {

                    socket.emit(
                        "profile error",
                        "Введите имя."
                    );

                    return;

                }


                if (
                    !validUsername(
                        username
                    )
                ) {

                    socket.emit(
                        "profile error",
                        "Юзернейм должен содержать от 5 до 20 символов и только английские буквы и цифры."
                    );

                    return;

                }


                if (
                    !isValidAvatar(
                        avatar
                    )
                ) {

                    socket.emit(
                        "profile error",
                        "Фотография слишком большая или имеет недопустимый формат."
                    );

                    return;

                }


                const anotherUser =
                    db.prepare(`
                        SELECT id
                        FROM users
                        WHERE
                            username = ?
                            AND id != ?
                    `).get(
                        username,
                        currentUser.id
                    );


                if (anotherUser) {

                    socket.emit(
                        "profile error",
                        "Такой username уже занят."
                    );

                    return;

                }


                db.prepare(`
                    UPDATE users
                    SET
                        username = ?,
                        display_name = ?,
                        about = ?,
                        avatar = ?
                    WHERE id = ?
                `).run(
                    username,
                    displayName,
                    about,
                    avatar,
                    currentUser.id
                );


                const updated =
                    db.prepare(`
                        SELECT
                            id,
                            username,
                            display_name,
                            about,
                            avatar
                        FROM users
                        WHERE id = ?
                    `).get(
                        currentUser.id
                    );


                socket.data.user =
                    updated;


                socket.emit(
                    "profile updated",
                    updated
                );


                /*
                    Если username изменился,
                    остальные клиенты должны
                    получить новый статус.
                */

                emitOnlineStatus(
                    username,
                    true
                );


                socket.emit(
                    "chats",
                    getChats(
                        username
                    )
                );

            }
        );


        /* =====================================================
           PRIVATE MESSAGE
        ===================================================== */

        socket.on(
            "private message",
            data => {

                const sender =
                    socket.data.user;

                if (!sender) {
                    return;
                }


                const recipient =
                    normalizeUsername(
                        data?.to
                    );

                const text =
                    cleanText(
                        data?.text,
                        4000
                    );


                if (
                    !validUsername(
                        recipient
                    )
                ) {
                    return;
                }


                if (!text) {
                    return;
                }


                if (
                    recipient ===
                    sender.username
                ) {
                    return;
                }


                const recipientUser =
                    db.prepare(`
                        SELECT
                            id,
                            username,
                            display_name,
                            about,
                            avatar
                        FROM users
                        WHERE username = ?
                    `).get(
                        recipient
                    );


                if (!recipientUser) {

                    socket.emit(
                        "message error",
                        "Пользователь не найден."
                    );

                    return;

                }


                const online =
                    isOnline(
                        recipient
                    );


                /*
                    Если пользователь прямо
                    сейчас онлайн, считаем сообщение
                    доставленным.

                    Прочитанным оно станет только
                    после открытия чата.
                */

                const result =
                    db.prepare(`
                        INSERT INTO messages
                        (
                            sender,
                            recipient,
                            text,
                            is_read
                        )
                        VALUES (?, ?, ?, 0)
                    `).run(
                        sender.username,
                        recipient,
                        text
                    );


                const message = {

                    id:
                        Number(
                            result.lastInsertRowid
                        ),

                    from:
                        sender.username,

                    to:
                        recipient,

                    text,

                    created_at:
                        new Date().toISOString(),

                    delivered:
                        online,

                    read:
                        false

                };


                /*
                    Отправителю.
                */

                socket.emit(
                    "private message",
                    message
                );


                /*
                    Получателю.
                */

                const recipientSockets =
                    onlineUsers.get(
                        recipient
                    );


                if (
                    recipientSockets &&
                    recipientSockets.size
                ) {

                    for (
                        const socketId
                        of recipientSockets
                    ) {

                        io.to(
                            socketId
                        ).emit(
                            "private message",
                            message
                        );

                    }

                }


                /*
                    Уведомление.
                */

                if (
                    recipientSockets &&
                    recipientSockets.size
                ) {

                    for (
                        const socketId
                        of recipientSockets
                    ) {

                        io.to(
                            socketId
                        ).emit(
                            "notification",
                            {
                                from:
                                    sender.username,

                                display_name:
                                    sender.display_name,

                                avatar:
                                    sender.avatar,

                                online:
                                    true,

                                text
                            }
                        );

                    }

                }

            }
        );


        /* =====================================================
           GET HISTORY
        ===================================================== */

        socket.on(
            "get history",
            data => {

                const user =
                    socket.data.user;

                if (!user) {
                    return;
                }


                const other =
                    normalizeUsername(
                        data?.user
                    );


                if (
                    !validUsername(
                        other
                    )
                ) {
                    return;
                }


                const history =
                    db.prepare(`
                        SELECT
                            id,
                            sender,
                            recipient,
                            text,
                            is_read,
                            created_at
                        FROM messages
                        WHERE
                            (
                                sender = ?
                                AND recipient = ?
                            )
                            OR
                            (
                                sender = ?
                                AND recipient = ?
                            )
                        ORDER BY id ASC
                    `).all(
                        user.username,
                        other,
                        other,
                        user.username
                    );


                socket.emit(
                    "chat history",
                    history.map(
                        message => ({
                            ...message,

                            delivered:
                                true,

                            read:
                                Boolean(
                                    message.is_read
                                )
                        })
                    )
                );


                /*
                    Открытие истории означает,
                    что входящие сообщения этого
                    пользователя прочитаны.
                */

                const unread =
                    db.prepare(`
                        SELECT id, sender
                        FROM messages
                        WHERE
                            sender = ?
                            AND recipient = ?
                            AND is_read = 0
                    `).all(
                        other,
                        user.username
                    );


                if (unread.length) {

                    db.prepare(`
                        UPDATE messages
                        SET is_read = 1
                        WHERE
                            sender = ?
                            AND recipient = ?
                            AND is_read = 0
                    `).run(
                        other,
                        user.username
                    );


                    /*
                        Отправляем отправителю
                        информацию о прочтении.
                    */

                    const senderSockets =
                        onlineUsers.get(
                            other
                        );


                    if (
                        senderSockets &&
                        senderSockets.size
                    ) {

                        const ids =
                            unread.map(
                                item =>
                                    item.id
                            );


                        for (
                            const socketId
                            of senderSockets
                        ) {

                            io.to(
                                socketId
                            ).emit(
                                "messages read",
                                {
                                    with:
                                        user.username,

                                    ids
                                }
                            );

                        }

                    }

                }

            }
        );


        /* =====================================================
           REQUEST USERS
           Оставлено для совместимости
           со старым клиентом.
        ===================================================== */

        socket.on(
            "request users",
            () => {

                const users = [];

                for (
                    const username
                    of onlineUsers.keys()
                ) {

                    users.push(
                        username
                    );

                }


                socket.emit(
                    "users",
                    users
                );

            }
        );


        /* =====================================================
           LOGOUT
        ===================================================== */

        socket.on(
            "logout",
            () => {

                const user =
                    socket.data.user;

                const token =
                    socket.data.sessionToken;


                deleteSession(
                    token
                );


                if (user) {

                    setOffline(
                        user.username,
                        socket.id
                    );


                    if (
                        !isOnline(
                            user.username
                        )
                    ) {

                        emitOnlineStatus(
                            user.username,
                            false
                        );

                    }

                }


                socket.data.user =
                    null;

                socket.data.sessionToken =
                    null;


                socket.emit(
                    "logged out"
                );

            }
        );


        /* =====================================================
           DISCONNECT
        ===================================================== */

        socket.on(
            "disconnect",
            reason => {

                const user =
                    socket.data.user;


                if (user) {

                    setOffline(
                        user.username,
                        socket.id
                    );


                    /*
                        Если у пользователя больше
                        нет Socket.IO соединений,
                        он действительно офлайн.
                    */

                    if (
                        !isOnline(
                            user.username
                        )
                    ) {

                        emitOnlineStatus(
                            user.username,
                            false
                        );

                    }

                }


                console.log(
                    "Socket отключён:",
                    socket.id,
                    reason
                );

            }
        );

    }
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/health",
    (req, res) => {

        res.status(200).json({
            status: "ok",
            app: "Nexgram",
            time:
                new Date().toISOString()
        });

    }
);


/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        if (
            req.path.startsWith(
                "/api/"
            )
        ) {

            return res.status(404).json({
                error: "API route not found."
            });

        }


        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );

    }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Server error:",
            error
        );


        if (res.headersSent) {
            return next(error);
        }


        res.status(500).json({
            error:
                "Внутренняя ошибка сервера."
        });

    }
);


/* =========================================================
   START
========================================================= */

server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log("");
        console.log(
            "================================="
        );

        console.log(
            "        NEXGRAM SERVER"
        );

        console.log(
            "================================="
        );

        console.log(
            `Порт: ${PORT}`
        );

        console.log(
            `Режим: ${
                isProduction
                    ? "production"
                    : "development"
            }`
        );

        console.log(
            "Health: /health"
        );

        console.log(
            "================================="
        );

    }
);


/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(
    signal
) {

    console.log(
        `${signal}: останавливаем Nexgram...`
    );


    io.close(() => {

        try {

            db.pragma(
                "wal_checkpoint(TRUNCATE)"
            );

        } catch (error) {

            console.error(
                "Ошибка checkpoint:",
                error
            );

        }


        db.close();

        server.close(
            () => {

                console.log(
                    "Nexgram остановлен."
                );

                process.exit(0);

            }
        );

    });

}


process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);