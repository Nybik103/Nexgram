const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const { Server } = require("socket.io");

/* =========================================================
   NEXGRAM SERVER
   PostgreSQL + Express + Socket.IO
   ========================================================= */

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT) || 3000;

const SESSION_COOKIE = "nexgram_session";
const SESSION_DAYS = 30;

const isProduction =
    process.env.NODE_ENV === "production";

/* =========================================================
   DATABASE
   ========================================================= */

if (!process.env.DATABASE_URL) {
    console.error("");
    console.error("========================================");
    console.error("NEXGRAM DATABASE ERROR");
    console.error("========================================");
    console.error("DATABASE_URL не найден.");
    console.error("");
    console.error(
        "Добавь DATABASE_URL в Environment Variables."
    );
    console.error("========================================");
    console.error("");

    process.exit(1);
}

const pool = new Pool({
    connectionString:
        process.env.DATABASE_URL,

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000,

    ssl: isProduction
        ? {
              rejectUnauthorized: false
          }
        : false
});

pool.on("error", error => {
    console.error(
        "PostgreSQL pool error:",
        error
    );
});

/* =========================================================
   SOCKET.IO
   ========================================================= */

const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true
    },

    maxHttpBufferSize:
        2 * 1024 * 1024
});

/* =========================================================
   EXPRESS
   ========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "2mb"
    })
);

app.use(cookieParser());

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

/* =========================================================
   DATABASE INITIALIZATION
   ========================================================= */

async function initializeDatabase() {
    console.log(
        "Подключение к PostgreSQL..."
    );

    await pool.query(
        "SELECT NOW()"
    );

    /*
        USERS
    */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            display_name TEXT NOT NULL DEFAULT '',

            about TEXT NOT NULL DEFAULT '',

            avatar TEXT NOT NULL DEFAULT '',

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    /*
        MESSAGES
    */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id BIGSERIAL PRIMARY KEY,

            sender TEXT NOT NULL,

            recipient TEXT NOT NULL,

            text TEXT NOT NULL,

            is_read BOOLEAN NOT NULL DEFAULT FALSE,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    /*
        SESSIONS
    */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS sessions (
            id BIGSERIAL PRIMARY KEY,

            user_id BIGINT NOT NULL,

            token_hash TEXT UNIQUE NOT NULL,

            expires_at TIMESTAMPTZ NOT NULL,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            CONSTRAINT fk_sessions_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
    `);

    /*
        INDEXES
    */

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_users_username
        ON users(username)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_sessions_token
        ON sessions(token_hash)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_sessions_expiry
        ON sessions(expires_at)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_messages_conversation
        ON messages(sender, recipient, id)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_messages_recipient_read
        ON messages(recipient, is_read)
    `);

    console.log(
        "PostgreSQL подключён."
    );

    console.log(
        "Таблицы Nexgram готовы."
    );
}

/* =========================================================
   PASSWORD HASHING
   ========================================================= */

/*
    Формат:

    scrypt$N$r$p$salt$hash
*/

function hashPassword(password) {
    const salt =
        crypto
            .randomBytes(16)
            .toString("hex");

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
        )
        .toString("hex");

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
            String(stored || "")
                .split("$");

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
            )
            .toString("hex");

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

        if (
            a.length !==
            b.length
        ) {
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

function cleanText(value, maxLength) {
    return String(value || "")
        .trim()
        .slice(0, maxLength);
}

function isValidAvatar(avatar) {
    if (!avatar) {
        return true;
    }

    if (
        !avatar.startsWith(
            "data:image/"
        )
    ) {
        return false;
    }

    if (
        Buffer.byteLength(
            avatar,
            "utf8"
        ) >
        1.5 * 1024 * 1024
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

async function createSession(userId) {
    const token =
        crypto
            .randomBytes(48)
            .toString("hex");

    const tokenHash =
        hashToken(token);

    const expiresAt =
        new Date(
            Date.now() +
            SESSION_DAYS *
                24 *
                60 *
                60 *
                1000
        );

    await pool.query(
        `
        INSERT INTO sessions
        (
            user_id,
            token_hash,
            expires_at
        )
        VALUES
        ($1, $2, $3)
        `,
        [
            userId,
            tokenHash,
            expiresAt
        ]
    );

    return {
        token,
        expiresAt
    };
}

async function deleteSession(token) {
    if (!token) {
        return;
    }

    await pool.query(
        `
        DELETE FROM sessions
        WHERE token_hash = $1
        `,
        [
            hashToken(token)
        ]
    );
}

async function getUserBySession(token) {
    if (!token) {
        return null;
    }

    const result =
        await pool.query(
            `
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
                s.token_hash = $1

                AND s.expires_at > NOW()

            LIMIT 1
            `,
            [
                hashToken(token)
            ]
        );

    return (
        result.rows[0] ||
        null
    );
}

/* =========================================================
   COOKIE
   ========================================================= */

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
   COOKIE PARSER
   ========================================================= */

function getSessionTokenFromCookie(
    cookieHeader
) {
    if (!cookieHeader) {
        return null;
    }

    const parts =
        cookieHeader.split(";");

    for (
        const part of parts
    ) {
        const pieces =
            part.trim()
                .split("=");

        const key =
            pieces.shift();

        if (
            key === SESSION_COOKIE
        ) {
            try {
                return decodeURIComponent(
                    pieces.join("=")
                );
            } catch {
                return null;
            }
        }
    }

    return null;
}

/* =========================================================
   AUTH MIDDLEWARE
   ========================================================= */

async function requireAuth(
    req,
    res,
    next
) {
    try {
        const token =
            req.cookies[
                SESSION_COOKIE
            ];

        const user =
            await getUserBySession(
                token
            );

        if (!user) {
            return res
                .status(401)
                .json({
                    error:
                        "Не авторизован."
                });
        }

        req.user = user;

        next();

    } catch (error) {
        next(error);
    }
}

/* =========================================================
   CLEAN EXPIRED SESSIONS
   ========================================================= */

async function cleanExpiredSessions() {
    try {
        await pool.query(
            `
            DELETE FROM sessions
            WHERE expires_at <= NOW()
            `
        );
    } catch (error) {
        console.error(
            "Ошибка очистки сессий:",
            error
        );
    }
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

function addOnlineUser(
    username,
    socketId
) {
    const key =
        normalizeUsername(
            username
        );

    if (!onlineUsers.has(key)) {
        onlineUsers.set(
            key,
            new Set()
        );
    }

    onlineUsers
        .get(key)
        .add(socketId);
}

function removeOnlineUser(
    username,
    socketId
) {
    const key =
        normalizeUsername(
            username
        );

    const sockets =
        onlineUsers.get(key);

    if (!sockets) {
        return;
    }

    sockets.delete(socketId);

    if (sockets.size === 0) {
        onlineUsers.delete(key);
    }
}

function isUserOnline(username) {
    return onlineUsers.has(
        normalizeUsername(username)
    );
}
/* =========================================================
   ONLINE USERS
   ========================================================= */

function setOnline(
    username,
    socketId
) {
    if (
        !onlineUsers.has(
            username
        )
    ) {
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
        onlineUsers.get(
            username
        );

    if (!sockets) {
        return;
    }

    sockets.delete(
        socketId
    );

    if (
        sockets.size === 0
    ) {
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
   USER HELPERS
   ========================================================= */

async function getProfile(
    username
) {
    const result =
        await pool.query(
            `
            SELECT
                username,
                display_name,
                about,
                avatar

            FROM users

            WHERE username = $1

            LIMIT 1
            `,
            [
                username
            ]
        );

    return (
        result.rows[0] ||
        null
    );
}

async function getUserByUsername(
    username
) {
    const result =
        await pool.query(
            `
            SELECT
                id,
                username,
                display_name,
                about,
                avatar

            FROM users

            WHERE username = $1

            LIMIT 1
            `,
            [
                username
            ]
        );

    return (
        result.rows[0] ||
        null
    );
}

/* =========================================================
   CHAT LIST
   ========================================================= */

async function getChats(
    username
) {
    const result =
        await pool.query(
            `
            SELECT
                m.id,

                CASE
                    WHEN m.sender = $1
                    THEN m.recipient
                    ELSE m.sender
                END AS other_username,

                m.text,

                m.created_at

            FROM messages m

            WHERE
                m.sender = $1
                OR m.recipient = $1

            ORDER BY m.id DESC
            `,
            [
                username
            ]
        );

    const chats = [];
    const seen = new Set();

    for (
        const row of result.rows
    ) {
        const other =
            row.other_username;

        if (
            seen.has(other)
        ) {
            continue;
        }

        seen.add(other);

        const profile =
            await getProfile(
                other
            );

        if (!profile) {
            continue;
        }

        chats.push({
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

    return chats;
}

/* =========================================================
   HTTP AUTH ROUTES
   ========================================================= */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {
        res.json({
            user: req.user
        });
    }
);

app.post(
    "/api/session",
    async (req, res) => {
        try {
            const token =
                String(
                    req.body?.token ||
                    ""
                );

            const user =
                await getUserBySession(
                    token
                );

            if (!user) {
                return res
                    .status(401)
                    .json({
                        error:
                            "Сессия недействительна."
                    });
            }

            setSessionCookie(
                res,
                token
            );

            res.json({
                success: true,
                user
            });

        } catch (error) {
            console.error(
                "Session error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Ошибка сервера."
                });
        }
    }
);

/*
    Выход.
*/

app.post(
    "/api/logout",
    async (req, res) => {
        try {
            const token =
                req.cookies[
                    SESSION_COOKIE
                ];

            await deleteSession(
                token
            );

            clearSessionCookie(
                res
            );

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "Logout error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Ошибка выхода."
                });
        }
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
            Проверяем cookie.
        */

        const cookieHeader =
            socket.handshake
                .headers
                .cookie || "";

        let sessionToken =
            getSessionTokenFromCookie(
                cookieHeader
            );

        /*
            Также поддерживаем токен
            через Socket.IO auth.
        */

        if (
            !sessionToken &&
            socket.handshake.auth &&
            socket.handshake.auth.token
        ) {
            sessionToken =
                String(
                    socket.handshake
                        .auth
                        .token
                );
        }

        /*
            Восстанавливаем сессию.
        */

        (async () => {
            try {
                if (!sessionToken) {
                    return;
                }

                const sessionUser =
                    await getUserBySession(
                        sessionToken
                    );

                if (!sessionUser) {
                    return;
                }

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

                socket.emit(
                    "auth success",
                    sessionUser.username
                );

            } catch (error) {
                console.error(
                    "Session restore error:",
                    error
                );
            }
        })();

        /* =====================================================
           РЕГИСТРАЦИЯ
        ===================================================== */

        socket.on(
            "register account",
            async data => {

                try {

                    const username =
                        normalizeUsername(
                            data?.username
                        );

                    const password =
                        String(
                            data?.password ||
                            ""
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
                        await pool.query(
                            `
                            SELECT id

                            FROM users

                            WHERE username = $1

                            LIMIT 1
                            `,
                            [
                                username
                            ]
                        );

                    if (
                        existing.rows.length
                    ) {
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
                        await pool.query(
                            `
                            INSERT INTO users
                            (
                                username,
                                password,
                                display_name,
                                about,
                                avatar
                            )

                            VALUES
                            (
                                $1,
                                $2,
                                $3,
                                '',
                                ''
                            )

                            RETURNING
                                id,
                                username,
                                display_name,
                                about,
                                avatar
                            `,
                            [
                                username,
                                passwordHash,
                                displayName
                            ]
                        );

                    const user =
                        result.rows[0];

                    const session =
                        await createSession(
                            user.id
                        );

                    socket.data.user =
                        user;

                    socket.data.sessionToken =
                        session.token;

                    setOnline(
                        username,
                        socket.id
                    );

                    emitOnlineStatus(
                        username,
                        true
                    );

                    socket.emit(
                        "auth success",
                        username
                    );

                    socket.emit(
                        "session created",
                        {
                            token:
                                session.token
                        }
                    );

                    socket.emit(
                        "profile",
                        user
                    );

                    socket.emit(
                        "chats",
                        []
                    );

                } catch (error) {

                    console.error(
                        "Ошибка регистрации:",
                        error
                    );

                    if (
                        error.code ===
                        "23505"
                    ) {
                        socket.emit(
                            "auth error",
                            "Такой username уже занят."
                        );

                        return;
                    }

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
            async data => {

                try {

                    const username =
                        normalizeUsername(
                            data?.username
                        );

                    const password =
                        String(
                            data?.password ||
                            ""
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

                    const result =
                        await pool.query(
                            `
                            SELECT
                                id,
                                username,
                                password,
                                display_name,
                                about,
                                avatar

                            FROM users

                            WHERE username = $1

                            LIMIT 1
                            `,
                            [
                                username
                            ]
                        );

                    const user =
                        result.rows[0];
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
                        await createSession(
                            user.id
                        );

                    const safeUser = {
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

                    socket.data.user =
                        safeUser;

                    socket.data.sessionToken =
                        session.token;

                    setOnline(
                        user.username,
                        socket.id
                    );

                    emitOnlineStatus(
                        user.username,
                        true
                    );

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

                    socket.emit(
                        "profile",
                        safeUser
                    );

                    socket.emit(
                        "chats",
                        await getChats(
                            user.username
                        )
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
            async data => {

                try {

                    const token =
                        String(
                            data?.token ||
                            ""
                        );

                    const user =
                        await getUserBySession(
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

                    socket.emit(
                        "auth success",
                        user.username
                    );

                    socket.emit(
                        "profile",
                        user
                    );

                    socket.emit(
                        "chats",
                        await getChats(
                            user.username
                        )
                    );

                } catch (error) {

                    console.error(
                        "Set session error:",
                        error
                    );

                    socket.emit(
                        "session error",
                        "Ошибка восстановления сессии."
                    );
                }
            }
        );

        /* =====================================================
           REGISTER / ONLINE
        ===================================================== */

        socket.on(
            "register",
            async username => {

                try {

                    const user =
                        socket.data.user;

                    if (!user) {
                        socket.emit(
                            "auth error",
                            "Сначала войдите в аккаунт."
                        );

                        return;
                    }

                    const profile =
                        await getProfile(
                            user.username
                        );

                    socket.data.user =
                        {
                            ...profile,
                            id: user.id
                        };

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
                        profile
                    );

                    socket.emit(
                        "chats",
                        await getChats(
                            user.username
                        )
                    );

                } catch (error) {

                    console.error(
                        "Register event error:",
                        error
                    );
                }
            }
        );

        /* =====================================================
           REQUEST CHATS
        ===================================================== */

        socket.on(
            "request chats",
            async () => {

                try {

                    const user =
                        socket.data.user;

                    if (!user) {
                        return;
                    }

                    socket.emit(
                        "chats",
                        await getChats(
                            user.username
                        )
                    );

                } catch (error) {

                    console.error(
                        "Chats error:",
                        error
                    );
                }
            }
        );

        /* =====================================================
           GET PROFILE
        ===================================================== */

        socket.on(
            "get profile",
            async () => {

                try {

                    const user =
                        socket.data.user;

                    if (!user) {
                        return;
                    }

                    const profile =
                        await getProfile(
                            user.username
                        );

                    socket.emit(
                        "profile",
                        profile
                    );

                } catch (error) {

                    console.error(
                        "Profile error:",
                        error
                    );
                }
            }
        );

        /* =====================================================
           SEARCH USERS
        ===================================================== */

        socket.on(
            "search users",
            async data => {

                try {

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

                    const result =
                        await pool.query(
                            `
                            SELECT
                                username,
                                display_name,
                                about,
                                avatar

                            FROM users

                            WHERE
                                username ILIKE $1

                                AND username != $2

                            ORDER BY username

                            LIMIT 20
                            `,
                            [
                                `%${query}%`,
                                user.username
                            ]
                        );

                    socket.emit(
                        "search results",
                        result.rows
                    );

                } catch (error) {

                    console.error(
                        "Search error:",
                        error
                    );

                    socket.emit(
                        "search results",
                        []
                    );
                }
            }
        );

        /* =====================================================
           GET PUBLIC PROFILE
        ===================================================== */

        socket.on(
            "get public profile",
            async data => {

                try {

                    const currentUser =
                        socket.data.user;

                    if (!currentUser) {
                        return;
                    }

                    const username =
                        normalizeUsername(
                            data?.username
                        );

                    if (
                        !username ||
                        username ===
                            currentUser.username
                    ) {
                        return;
                    }

                    const profile =
                        await getProfile(
                            username
                        );

                    socket.emit(
                        "public profile",
                        profile || null
                    );

                } catch (error) {

                    console.error(
                        "Public profile error:",
                        error
                    );

                    socket.emit(
                        "public profile",
                        null
                    );
                }
            }
        );

        /* =====================================================
           UPDATE PROFILE
        ===================================================== */

        socket.on(
            "update profile",
            async data => {

                try {

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
                            data?.avatar ||
                            ""
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
                        await pool.query(
                            `
                            SELECT id

                            FROM users

                            WHERE
                                username = $1

                                AND id != $2

                            LIMIT 1
                            `,
                            [
                                username,
                                currentUser.id
                            ]
                        );

                    if (
                        anotherUser.rows.length
                    ) {
                        socket.emit(
                            "profile error",
                            "Такой username уже занят."
                        );

                        return;
                    }

                    const oldUsername =
                        currentUser.username;

                    const client =
                        await pool.connect();

                    try {

                        await client.query(
                            "BEGIN"
                        );

                        if (
                            oldUsername !==
                            username
                        ) {

                            await client.query(
                                `
                                UPDATE messages

                                SET sender =
                                    CASE
                                        WHEN sender = $1
                                        THEN $2
                                        ELSE sender
                                    END,

                                    recipient =
                                    CASE
                                        WHEN recipient = $1
                                        THEN $2
                                        ELSE recipient
                                    END

                                WHERE
                                    sender = $1
                                    OR recipient = $1
                                `,
                                [
                                    oldUsername,
                                    username
                                ]
                            );
                        }

                        await client.query(
                            `
                            UPDATE users

                            SET
                                username = $1,
                                display_name = $2,
                                about = $3,
                                avatar = $4

                            WHERE id = $5
                            `,
                            [
                                username,
                                displayName,
                                about,
                                avatar,
                                currentUser.id
                            ]
                        );

                        await client.query(
                            "COMMIT"
                        );

                    } catch (error) {

                        await client.query(
                            "ROLLBACK"
                        );

                        throw error;

                    } finally {

                        client.release();
                    }

                    if (
                        oldUsername !==
                        username
                    ) {

                        setOffline(
                            oldUsername,
                            socket.id
                        );

                        if (
                            !isOnline(
                                oldUsername
                            )
                        ) {
                            emitOnlineStatus(
                                oldUsername,
                                false
                            );
                        }
                    }

                    setOnline(
                        username,
                        socket.id
                    );

                    const updated =
                        await getProfile(
                            username
                        );

                    socket.data.user =
                        {
                            ...updated,
                            id:
                                currentUser.id
                        };

                    socket.emit(
                        "profile updated",
                        socket.data.user
                    );

                    emitOnlineStatus(
                        username,
                        true
                    );

                    socket.emit(
                        "chats",
                        await getChats(
                            username
                        )
                    );

                } catch (error) {

                    console.error(
                        "Ошибка обновления профиля:",
                        error
                    );

                    if (
                        error.code ===
                        "23505"
                    ) {
                        socket.emit(
                            "profile error",
                            "Такой username уже занят."
                        );

                        return;
                    }

                    socket.emit(
                        "profile error",
                        "Не удалось обновить профиль."
                    );
                }
            }
        );
        /* =====================================================
           PRIVATE MESSAGE
        ===================================================== */

        socket.on(
            "private message",
            async data => {

                try {

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
                        await getUserByUsername(
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

                    const result =
                        await pool.query(
                            `
                            INSERT INTO messages
                            (
                                sender,
                                recipient,
                                text,
                                is_read
                            )

                            VALUES
                            (
                                $1,
                                $2,
                                $3,
                                FALSE
                            )

                            RETURNING
                                id,
                                sender,
                                recipient,
                                text,
                                is_read,
                                created_at
                            `,
                            [
                                sender.username,
                                recipient,
                                text
                            ]
                        );

                    const row =
                        result.rows[0];

                    const message = {
                        id:
                            Number(
                                row.id
                            ),

                        from:
                            row.sender,

                        to:
                            row.recipient,

                        sender:
                            row.sender,

                        recipient:
                            row.recipient,

                        text:
                            row.text,

                        created_at:
                            row.created_at,

                        delivered:
                            online,

                        read:
                            Boolean(
                                row.is_read
                            )
                    };

                    socket.emit(
                        "private message",
                        message
                    );

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

                } catch (error) {

                    console.error(
                        "Message error:",
                        error
                    );

                    socket.emit(
                        "message error",
                        "Не удалось отправить сообщение."
                    );
                }
            }
        );

        /* =====================================================
           GET HISTORY
        ===================================================== */

        socket.on(
            "get history",
            async data => {

                try {

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

                    const historyResult =
                        await pool.query(
                            `
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
                                    sender = $1
                                    AND recipient = $2
                                )

                                OR

                                (
                                    sender = $2
                                    AND recipient = $1
                                )

                            ORDER BY id ASC
                            `,
                            [
                                user.username,
                                other
                            ]
                        );

                    const history =
                        historyResult.rows.map(
                            message => ({
                                id:
                                    Number(
                                        message.id
                                    ),

                                sender:
                                    message.sender,

                                recipient:
                                    message.recipient,

                                from:
                                    message.sender,

                                to:
                                    message.recipient,

                                text:
                                    message.text,

                                is_read:
                                    Boolean(
                                        message.is_read
                                    ),

                                created_at:
                                    message.created_at
                            })
                        );

                    socket.emit(
                        "history",
                        {
                            username:
                                other,

                            messages:
                                history
                        }
                    );

                } catch (error) {

                    console.error(
                        "History error:",
                        error
                    );

                    socket.emit(
                        "history",
                        {
                            username:
                                data?.user,

                            messages:
                                []
                        }
                    );
                }
            }
        );
        /*
            Завершение обработчика
            Socket.IO.
        */

        socket.on(
            "typing",
            data => {
                const user =
                    socket.data.user;

                if (!user) {
                    return;
                }

                const recipient =
                    normalizeUsername(
                        data?.to
                    );

                if (
                    !validUsername(
                        recipient
                    )
                ) {
                    return;
                }

                const recipientSockets =
                    onlineUsers.get(
                        recipient
                    );

                if (
                    !recipientSockets ||
                    !recipientSockets.size
                ) {
                    return;
                }

                for (
                    const socketId
                    of recipientSockets
                ) {
                    io.to(
                        socketId
                    ).emit(
                        "typing",
                        {
                            from:
                                user.username,

                            typing:
                                Boolean(
                                    data?.typing
                                )
                        }
                    );
                }
            }
        );
/* =========================================================
   START
   ========================================================= */

async function startServer() {

    try {

        await initializeDatabase();

        await cleanExpiredSessions();

        server.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log("");

                console.log(
                    "================================="
                );

                console.log(
                    "          NEXGRAM SERVER"
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
                    "Database: PostgreSQL"
                );

                console.log(
                    "Health: /health"
                );

                console.log(
                    "================================="
                );

                console.log(
                    "Nexgram запущен."
                );

            }
        );

    } catch (error) {

        console.error("");

        console.error(
            "================================="
        );

        console.error(
            "NEXGRAM START ERROR"
        );

        console.error(
            "================================="
        );

        console.error(
            error
        );

        console.error(
            "================================="
        );

        process.exit(1);
    }
}

/* =========================================================
   GRACEFUL SHUTDOWN
   ========================================================= */

async function shutdown(
    signal
) {

    console.log(
        `${signal}: останавливаем Nexgram...`
    );

    io.close(
        async () => {

            server.close(
                async () => {

                    try {

                        await pool.end();

                        console.log(
                            "PostgreSQL pool закрыт."
                        );

                    } catch (error) {

                        console.error(
                            "Ошибка закрытия PostgreSQL:",
                            error
                        );
                    }

                    console.log(
                        "Nexgram остановлен."
                    );

                    process.exit(0);
                }
            );
        }
    );
}

process.on(
    "SIGTERM",
    () => {
        shutdown("SIGTERM");
    }
);

process.on(
    "SIGINT",
    () => {
        shutdown("SIGINT");
    }
);

/* =========================================================
   START
   ========================================================= */

startServer();