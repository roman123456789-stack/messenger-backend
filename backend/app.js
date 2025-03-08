const express = require('express');
const cors = require('cors');
// const https = require("https");
const http = require("http");
const fs = require("fs");
const bodyParser = require('body-parser');
const {Server} = require("socket.io");
const path = require('path');
const app = express();
const crypto = require("crypto");

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const PORT = 3001;
const options = {
    key: fs.readFileSync(__dirname + '/certs/server.key'),
    cert: fs.readFileSync(__dirname + '/certs/server.cert')
};
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "https://roman123456789-stack.github.io/messenger-frontend",
        methods: ["GET", "POST"]
    }
});

const multer = require("multer");
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads')); // Папка для сохранения файлов
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const extension = path.extname(file.originalname); // Получаем расширение файла
      cb(null, uniqueSuffix + extension); // Сохраняем файл с уникальным именем и расширением
    },
});
const upload = multer({
    storage,
    limits:{fileSize: 100 * 1024 * 1024}, // Ограничение 100МБ
});

const connection = require("./db/connection");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const token_jwt = require("./token/token");
const JWT_SECRET = token_jwt.token;

// ПРОВЕРКА ТОКЕНА ПЕРЕД ЗАПУСКОМ WEBSOCKET
io.use((socket, next)=>{
    const token = socket.handshake.auth.token;
    if (!token) {
        return next (new Error("Токен отсутствует"));
    };
    jwt.verify(token, JWT_SECRET, (err, decoded)=>{
        if (err) {
            return next (new Error("Токен не подтвержден"));
        }
        socket.userId = decoded.id;
        next();
    })
});
// WEBSOCKET
io.on('connection', async (socket) => {
    console.log('User connected:', socket.userId);
    
    // Создаем личную комнату для пользователя 
    socket.join(`user_${socket.userId}`);

     // Присоединяем пользователя ко всем его диалогам
    const [userDialogues] = await connection.promise().query(`
        SELECT group_id FROM group_members WHERE user_id = ?
    `, [socket.userId]);

    userDialogues.forEach((dialogue)=>{
        socket.join(`dialogue_${dialogue.group_id}`);
        console.log(`user ${socket.userId} joined dialogue_${dialogue.group_id}`);
    });
    socket.on("newDialogue", (dialogueId)=>{        
        socket.join(`dialogue_${dialogueId}`);
        console.log(`user ${socket.userId} joined new dialogue_${dialogueId}`);
    })
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.userId);
    });

    // socket.on("leaveDialogue", (groupId) => {
    //     socket.leave(`dialogue_${groupId}`);
    //     console.log(`User ${socket.userId} left dialog_${groupId}`);
    // });
});
// ПРОВЕРКА ТОКЕНА
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers["token"];
        if (!token) return res.status(401).json({ error: "Токен отсутствует" });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: "Неверный токен" });
    }
};

// РЕГИСТРАЦИЯ
app.post("/registration", async (req, res)=>{
    try {
        const {email, password} = req.body;
        const passwordHash = await bcrypt.hash(password, 10);
        const [isUserExist] = await connection.promise().query(`
            SELECT * FROM users WHERE user_email = ?
        `,[email]);
        if (isUserExist.length > 0) {
            return res.status(409).send("Пользователь с таким email уже существует");
        }
        const [result] = await connection.promise().query(`
            INSERT INTO users(user_email, user_password) VALUES (?, ?)
        `,[email, passwordHash]);

        const userId = result.insertId;
        const token = jwt.sign({id: userId, email: email }, JWT_SECRET, { expiresIn: "1d" });
        res.json({ message: 'Успешная регистрация', token});
        
    } catch (error) {
        res.status(500).send(`Ошибка регистрации ${error}`);
    }
})
// УДАЛЕНИЕ АККАНУТА
app.post("/api/delete/account", authMiddleware, async (req, res)=>{
    try {
        const userId = req.user.id;
        const result = await connection.promise().query(`
            UPDATE users SET users.is_deleted = 1
            WHERE users.user_id = ?    
        `, userId);
        res.status(200);
    } catch (error) {
        res.status(500);
    }
})
// АВТОРИЗАЦИЯ
app.post("/autorization", (req, res)=>{
    const {email, password} = req.body;
    try {
        const query = `
            SELECT * FROM users WHERE user_email = ? AND users.is_deleted <> 1
        `;
        connection.query(query, [email], (error, result)=>{
            if (error) {
                console.error(error);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }
            if(result.length === 0){
                return res.status(401).json({ message: 'Неверный email или пароль' });
            }
            const user = result[0];
            const isPasswordValid = bcrypt.compare(password, user.user_password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Неверный email или пароль' });
            }
            const token = jwt.sign({id: user.user_id, email: user.user_email}, JWT_SECRET, { expiresIn: "1d" });
            res.json({ message: 'Успешный вход', token: token});
        });
    } catch (error) {
        res.status(500).json({ message: "Ошибка авторизации" });
    }
})
// ПОЛУЧИТЬ СПИСОК ДИАЛОГОВ
app.get("/home/api/dialogues", authMiddleware, async (req, res)=>{
    try {
        const userId = req.user.id;
        const [rows] = await connection.promise().query(
            `SELECT 
                g.group_id,
                g.group_name,
                m.sended_at, 
                u.user_initials, 
                g.is_channel, 
                g.is_private, 
                g.is_common, 
                g.is_personal,
                m.message, 
                m.message_id, 
                media.media_type,
                gk.encryption_key
            FROM groups_table g
            INNER JOIN messages m ON g.group_id = m.group_id AND g.is_deleted <> 1
            LEFT JOIN media ON m.media_id = media.media_id
            INNER JOIN users u ON u.user_id = m.user_id AND u.is_deleted <> 1
            INNER JOIN group_members gm ON gm.group_id = g.group_id AND gm.user_id = ?
            INNER JOIN group_keys gk ON gk.group_id = g.group_id
            INNER JOIN (
                SELECT group_id, MAX(message_id) AS max_message_id
                FROM messages
                GROUP BY group_id
            ) last_messages ON m.group_id = last_messages.group_id AND m.message_id = last_messages.max_message_id
            ORDER BY m.sended_at DESC;`,
            [userId]
        );
        const [dialogueName] = await connection.promise().query(
        `SELECT DISTINCT
            CASE 
                WHEN g.is_personal = 1 THEN u2.user_initials
                ELSE g.group_name
            END AS dialogue_name,
            CASE 
                WHEN g.is_personal = 1 THEN p.image_path
                ELSE g.image_path
            END AS image_path,
            g.group_id
        FROM 
            groups_table g
        INNER JOIN 
            group_members gm1 ON g.group_id = gm1.group_id
        INNER JOIN 
            group_members gm2 ON g.group_id = gm2.group_id
        INNER JOIN 
            users u1 ON gm1.user_id = u1.user_id
        INNER JOIN 
            users u2 ON gm2.user_id = u2.user_id
        LEFT JOIN 
            profile_images p ON p.user_id = u2.user_id AND p.is_main = 1 AND p.is_deleted = 0
        WHERE
            g.is_deleted = 0
            AND gm1.user_id = ?
            AND gm2.user_id <> ?
            AND (g.is_common = 1 OR g.is_personal = 1);`, [userId, userId]
        );
        const [unviewedMessages] = await connection.promise().query(`
            SELECT group_id, COUNT(*) as total
                FROM messages_views
                WHERE user_id = ? AND is_viewed = ?
            GROUP BY group_id
        `, [userId, 0]);
        console.log(unviewedMessages);
        rows.forEach((row)=>{
            const findedDialogueNameAndImage = dialogueName.find(dialogue => dialogue.group_id === row.group_id);
            const findedDialogueUnviewedMessages = unviewedMessages.find(unviewed => unviewed.group_id === row.group_id);

            row.dialogue_name = findedDialogueNameAndImage ? findedDialogueNameAndImage.dialogue_name : undefined;
            row.image_path = findedDialogueNameAndImage ? findedDialogueNameAndImage.image_path : undefined;
            row.count_unread_messages = findedDialogueUnviewedMessages ? findedDialogueUnviewedMessages.total : undefined;
        })
        const result = {
            dialogues: rows,
            userId: userId,
        };
        console.log(result);
        res.status(200).json(result);
    } catch (error) {
        console.log(error.message);
        res.status(404).send(`Ошибка получения диалогов ${error}`);
    }
});
app.get("/api/status/other/user/:groupId", authMiddleware, async (req, res)=>{
    try {
        const userId = req.user.id;
        const groupId = req.params["groupId"];
        const [[result]] = await connection.promise().query(`
            SELECT u.user_last_time, u.user_status FROM users u
                INNER JOIN group_members gm ON gm.user_id = u.user_id
                INNER JOIN groups_table gt ON gt.group_id = gm.group_id
            WHERE u.user_id <> ? AND gt.is_deleted <> 1 AND u.is_deleted <> 1 AND gt.is_personal = 1 AND gt.group_id = ?    
        `, [userId, groupId]);
        res.status(200).json({result});
    } catch (error) {
        res.status(500).send(`Ошибка ${error}`);
    }
})
// ПОЛУЧИТЬ СООБЩЕНИЯ
app.get("/api/messages/:groupId", authMiddleware, async (req, res)=>{
    try {
        const {groupId} = req.params;
        const userId = req.user.id; 
        const limit = parseInt(req.query.limit) || 20; // Количество сообщений (default: 20)
        const offset = parseInt(req.query.offset) || 0; // Смещение (default: 0)
        const [messages] = await connection.promise().query(`
            SELECT
                message_id,
                user_id,
                group_id,
                message,
                sended_at,
                media.media_id,
                media_path,
                media_type,
                media_size,
                media_name
            FROM
                messages
            LEFT JOIN
                media ON messages.media_id = media.media_id
            WHERE
                messages.group_id = ?
            ORDER BY message_id DESC
            LIMIT ?
            OFFSET ?
        `, [groupId, limit, offset]);

        // Получаем ключ шифрования для диалога
        const [[keyRow]] = await connection.promise().query(`
            SELECT encryption_key FROM group_keys WHERE group_id = ?
        `, [groupId]);

        if (!keyRow) {
            return res.status(500).json({ error: "Ключ шифрования не найден" });
        }
        const encryptionKey = keyRow.encryption_key;

        const response = {
            userId: userId,
            messages: messages,
            encryptionKey: encryptionKey
        }
        console.log(response);
        if (messages.length < limit) {
            res.setHeader("X-No-More-Messages", "true"); // Указываем, что больше нет сообщений
        }
        res.json(response);
    } catch (error) {
        res.status(404).send(`Ошибка получения сообщений ${error}`);
    }
});

// ВСТАВКА СООБЩЕНИЯ
app.post("/api/insert/message/:dialogueId", authMiddleware, async (req, res)=>{
    try {
        console.log("Зашли в запрос");
        const message = req.body["message"];
        const {dialogueId} = req.params;
        const userId = req.user.id;
        
        //****************ПРОВЕРЯЕМ КОРРЕКТНОСТЬ И ДОСТУП***************//
        if (!message || message.trim().length === 0) {
            return res.status(400).json({ error: "Сообщение не может быть пустым" });
        }
        if (message.length > 2000) {
            return res.status(400).json({ error: "Сообщение слишком длинное" });
        }
        const [access] = await connection.promise().query(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            [dialogueId, userId]
        ); 
        if (access.length === 0) {
            return res.status(404).json({ error: "Нет доступа к диалогу" });
        }
        
        //**************ПОЛУЧАЕМ КЛЮЧ И ШИФРУЕМ СООБЩЕНИЯ****************//
        const [[key]] = await connection.promise().query(`
            SELECT encryption_key FROM group_keys WHERE group_id = ?    
            `, [dialogueId]);
            if (!key) {
                return res.status(500).json({ error: "Ключ шифрования не найден" });
            }
        const encryptionKey = key.encryption_key;
        const encryptedMessage = encryptMessage(message, encryptionKey);

        //***ВСТАЛЯЕМ СООБЩЕНИЕ В БАЗУ ДАННЫХ И ПОЛУЧАЕМ ЕГО ОБРАТНО***//
        const [query] = await connection.promise().query(`
            INSERT INTO messages (user_id, group_id, message) VALUES (?, ?, ?) 
        `, [userId, dialogueId, encryptedMessage]);

        const [[newMessage]] = await connection.promise().query(`
            SELECT m.message_id, m.sended_at, m.is_viewed, m.user_id, m.group_id, m.media_id, m.message, m.is_deleted, u.user_initials FROM messages m
				INNER JOIN users u ON u.user_id = m.user_id
	            WHERE m.message_id = ?
        `, [query.insertId]);

        // *************ОТМЕЧАЕМ СООБЩЕНИЕ КАК НЕПРОЧИТАННОЕ************//
        const [members] = await connection.promise().query(`
            SELECT user_id FROM group_members
                WHERE user_id <> ? AND group_id = ?
        `, [userId, dialogueId]);
        members.forEach(async (member)=>{
            const setInfo = await connection.promise().query(`
                INSERT INTO messages_views(message_id, user_id, group_id) VALUES (?, ?, ?)
            `, [query.insertId, member.user_id, dialogueId]);
        })


        //**ДИАЛОГ НОВЫЙ ? ПОЛУЧАЕМ ВСЕХ УЧАСТНИКОВ ДИАЛОГА И ОТПРАВЛЯЕМ ИМ СООБЩЕНИЯ СНАЧАЛА В ИХ ЛИЧНЫЕ КОМНАТЫ**//
        const [[messagesCount]] = await connection.promise().query(`
            SELECT COUNT(*) as count FROM messages WHERE messages.group_id = ?
        `, [dialogueId]);
        if (messagesCount["count"] === 1) {
            const [users] = await connection.promise().query(`
                SELECT * FROM group_members WHERE group_id = ?    
            `, [dialogueId]);
            await users.forEach(user => {
                io.to(`user_${user.user_id}`).emit("updateDialogues", dialogueId);
                io.to(`user_${user.user_id}`).emit("newMessage", newMessage);
            });
        }
        else{
            io.to(`dialogue_${dialogueId}`).emit("newMessage", newMessage);
        }

        // console.log(newMessage);
        res.status(200).json({message: "Сообщение получено сервером и отправлен ответ"});
    } catch (error) {
        console.log(error.message);
        res.status(500).send(`Ошибка отправки сообщения ${error}`);
    }
});
// Шифрование сообщения
function encryptMessage(message, key) {
    const iv = crypto.randomBytes(16); // Генерируем IV
    const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key, "hex"), iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");
    return `${iv.toString("hex")}:${encrypted}`;
}
// ВСТАВКА ФАЙЛОВ
app.post("/api/insert/files/:dialogueId", authMiddleware, upload.array("file"), async (req, res)=>{
    try {
        const {dialogueId} = req.params;
        const userId = req.user.id;
        const files = req["files"];
        if ((!files || files.length === 0) && !decoded) {
            res.status(413).send("Ошибка загрузки файлов");
        }
        for (const file of files){
            const filePath = "http://localhost:3001" + "/uploads/" + file.filename;
            const fileType = file.mimetype;
            const fileName = file.originalname;
            const filesize = (parseInt(file.size) / 1_048_576).toFixed(3);
            if (file.length > 500) {
                throw new Error("Название файла слишком большое");
            }
            try {
                const [result] = await connection.promise().query(`
                    INSERT INTO media(media_path, media_type, media_name, media_size) VALUES (?, ?, ?, ?)
                `, [filePath, fileType, fileName, filesize]);
                const mediaId = result.insertId;
                const [query] = await connection.promise().query(`
                    INSERT INTO messages(media_id, group_id, user_id) VALUES (?, ?, ?)
                `, [mediaId, dialogueId, userId]);
                const [[newMessage]] = await connection.promise().query(`
                    SELECT m.message_id, 
                           m.sended_at, 
                           m.is_viewed, 
                           m.user_id, 
                           m.group_id, 
                           m.media_id, 
                           m.message, 
                           m.is_deleted, 
                           u.user_initials, 
                           media.media_type, 
                           media.media_path, 
                           media.media_name 
                           FROM messages m
                        INNER JOIN users u ON u.user_id = m.user_id
                        INNER JOIN media ON media.media_id = m.media_id
                        WHERE m.message_id = ?
                `, [query.insertId]);
                 // *************ОТМЕЧАЕМ СООБЩЕНИЕ КАК НЕПРОЧИТАННОЕ************//
                const [members] = await connection.promise().query(`
                    SELECT user_id FROM group_members
                        WHERE user_id <> ? AND group_id = ?
                `, [userId, dialogueId]);
                members.forEach(async (member)=>{
                    const setInfo = await connection.promise().query(`
                        INSERT INTO messages_views(message_id, user_id, group_id) VALUES (?, ?, ?)
                    `, [query.insertId, member.user_id, dialogueId]);
                })
                
                const [[messagesCount]] = await connection.promise().query(`
                    SELECT COUNT(*) as count FROM messages WHERE messages.group_id = ?
                `, [dialogueId]);
                console.log(messagesCount);
                if (messagesCount["count"] === 1) {
                    const [users] = await connection.promise().query(`
                        SELECT * FROM group_members WHERE group_id = ?    
                    `, [dialogueId]);
                    await users.forEach(user => {
                        io.to(`user_${user.user_id}`).emit("updateDialogues", dialogueId);
                        io.to(`user_${user.user_id}`).emit("newMessage", newMessage);
                    });
                }
                else{
                    io.to(`dialogue_${dialogueId}`).emit("newMessage", newMessage);
                }
                console.log(newMessage);
                res.status(200).json({message: "Файлы получены сервером и отправлен ответ"});
            } catch (error) {
                console.log(error);
            }
        };
    } catch (error) {
        res.status(401).json({message: "Токен не подтвержден"});
        console.log(error);
    }
})
// ВЕРИФИКАЦИЯ ТОКЕНА
app.get("/verify", (req, res) => {
    try {
        const token = req.headers["token"];

        if (!token) {
            return res.status(401).json({ message: "Токен отсутствует" });
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        return res.json({ message: "Токен подтвержден", token });
    } catch (error) {
        console.log("Токен не подтвержден");
        return res.status(401).json({ message: "Неверный токен", error: error.message });
    }
});
// ПОИСК ЮЗЕРА
app.get("/search/:data", async (req, res)=>{
    const token = req.headers["token"];
    const data = req.params["data"];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if(!decoded){
            throw new Error("Неверный токен");
        }
        const userId = decoded.id;
        const [query] = await connection.promise().query(`
                SELECT
                    u.user_id, 
                    u.user_initials,
                    u.user_nickname, 
                    image_path 
                        FROM users u
	                    LEFT JOIN profile_images p ON p.user_id = u.user_id AND p.is_main = 1 AND p.is_deleted = 0
                    WHERE (u.user_nickname LIKE ? OR u.user_initials LIKE ?) AND u.user_id <> ?
        `, [`%${data}%`, `%${data}%`, userId]);
        res.json(query);
    } catch (error) {
        console.log(error.message);
        res.status(404);
    }
})
// ПОЛУЧИТЬ ПРОФИЛЬ ДРУГОГО ЮЗЕРА
app.get("/api/get/user/profile/:selectedDialogue", authMiddleware, async (req, res)=>{
    const userId = req.user.id;
    const groupId = req.params["selectedDialogue"];
    try {
        const [[user]] = await connection.promise().query(`
            SELECT users.user_id, users.user_initials, users.user_nickname, users.user_bio, users.user_last_time, users.user_birthday
                FROM group_members
                INNER JOIN users ON users.user_id = group_members.user_id
                WHERE group_members.group_id = ? AND users.user_id <> ?
        `, [groupId, userId]);
        const otherUserId = user.user_id;
        const [userImages] = await connection.promise().query(`
            SELECT * FROM profile_images
            WHERE profile_images.user_id = ?
            ORDER BY created_at DESC
        `, [otherUserId]);
        res.json({user: user, userImages: userImages});
    } catch (error) {
        res.status(404).send({message: "Ошибка получения данных"});
    }
});
// ПОЛУЧИТЬ СВОЙ ПРОФИЛЬ
app.get("/api/get/self/profile", authMiddleware, async (req, res)=>{
    const userId = req.user.id;
    try {
        console.log(userId);
        const [[user]] = await connection.promise().query(`
            SELECT users.user_id, users.user_initials, users.user_nickname, users.user_bio, users.user_last_time, users.user_birthday
                FROM users
                WHERE users.user_id = ?
        `, [userId]);
        const [userImages] = await connection.promise().query(`
            SELECT * FROM profile_images
                WHERE profile_images.user_id = ?
                ORDER BY created_at DESC
        `, [userId]);
        console.log(user);
        console.log(userImages);
        res.json({user: user, userImages: userImages});
    } catch (error) {
        res.status(500).send({message: "Ошибка получения данных"});
        console.log(error);
    }
});
// ОБНОВЛЕНИЕ ПРОФИЛЯ
app.post("/api/update/self/profile/:updatedFields", authMiddleware, async (req, res)=>{
    const userId = req.user.id;
    const updatedFileds = JSON.parse(req.params["updatedFields"]);
    try {
        const birthday = (updatedFileds.user_birthday).split("T")[0];
        const query = await connection.promise().query(`
            UPDATE users
            SET user_nickname = ?, user_birthday = ?, user_bio = ?, user_initials = ?    
            WHERE user_id = ?
        `, [
                updatedFileds.user_nickname, 
                birthday, 
                updatedFileds.user_bio, 
                updatedFileds.user_initials, 
                userId
            ]);
        res.status(200).send({message: "Данные успешно загружены"});
    } catch (error) {
        res.status(500);
        console.log(error.message);
    }
})
// ПРОВЕРКА НИКНЕЙМА
app.get("/api/check/nickname/is/valid/:nickname", authMiddleware, async (req, res)=>{
    const nickname = req.params["nickname"];
    try {
        const [result] = await connection.promise().query(`
            SELECT * FROM users
            WHERE users.user_nickname = ?    
        `, [nickname]);
        if (result.length > 0) {
            return res.status(200).json({user: result});
        }
        else{
            return res.status(200).json({user: null});
        }
    } catch (error) {
        res.status(409);
        return console.log(error.message);  
    }
})

// СУЩЕСТВУЕТ ЛИ ДИАЛОГ С ТАКИМИ ЮЗЕРАМИ ДЛЯ ЛИЧНЫХ ЧАТОВ
app.get("/api/check/group/is/exist/:userId", authMiddleware, async (req, res)=>{
    const user = req.user.id;
    const userRequested = req.params["userId"];
    try {
        console.log(user);
        console.log(userRequested);
        const [[result]] = await connection.promise().query(`
            SELECT gm.group_id
                FROM group_members gm
                INNER JOIN groups_table g ON gm.group_id = g.group_id
                WHERE g.is_personal = 1 AND g.is_deleted <> 1
                AND gm.user_id IN (?, ?)
                GROUP BY gm.group_id
                HAVING COUNT(DISTINCT gm.user_id) = 2;
        `, [user, userRequested]);
        if (result && result.group_id) { //Существует - отправлем id диалога
            console.log(`Диалог существует ${result.group_id}`);
            return res.status(200).json({group_id: result.group_id});
        }
        return res.status(200).json({group_id: null}); //Не существует null
    } catch (error) {
        console.log(error.message)
        return res.status(500);
    }
});
// ДИАЛОГ НЕ СУЩЕСТВУЕТ ? СОЗДАЕМ ДИАЛОГ
app.post("/api/create/new/group/:userRequested", authMiddleware, async (req, res)=>{
    const userId = req.user.id;
    const userRequested = req.params["userRequested"];
    try {
        const [createPersonalGroup] = await connection.promise().query(`
            INSERT INTO groups_table(is_personal) VALUE (1)
        `);
        const groupId = createPersonalGroup.insertId;
        const encryptionKey = crypto.randomBytes(32).toString("hex");//Ключ для диалога
        await connection.promise().query(`
            INSERT INTO group_keys (group_id, encryption_key) VALUES (?, ?)
        `, [groupId, encryptionKey]);
        const insertUsersIntoGroup = await connection.promise().query(`
            INSERT INTO group_members(group_id, user_id) VALUES (?, ?), (?, ?)
        `, [groupId, userId, groupId, userRequested]);
        console.log(`Диалог создан ${groupId}`);
        return res.status(200).json({group_id: groupId});
    } catch (error) {
        console.log(error.message)
        return res.status(500);
    }
});
// УСТАНОВКА СВОЕЙ ФОТОГРАФИИ ПРОФИЛЯ
app.post("/api/insert/profile/photo", authMiddleware, upload.single("file"), async (req, res)=>{
    const userId = req.user.id;
    const photo = req["file"];
    const filePath = "http://localhost:3001" + "/uploads/" + photo.filename;
    try {
        const [rows] = await connection.promise().query(`
            SELECT COUNT(*) AS total FROM profile_images WHERE user_id = ?    
        `, [userId]);
        const checkCountPhoto = rows[0].total;
        if (checkCountPhoto > 30) {
            throw new Error("Количество изображений должно быть меньше 30!");
        }
        // Делаем все остальные фотот у юзера не главными
        const updateQuery = await connection.promise().query(`
            UPDATE profile_images SET is_main = 0 WHERE user_id = ?    
        `, [userId]);
        // Добавляем новое фото
        const query = await connection.promise().query(`
            INSERT INTO profile_images(image_path, user_id, is_main) VALUES (?, ?, ?)
        `, [filePath, userId, 1]);
        res.status(200).json({message: "Фото профиля успешно сохранено"});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Ошибка сервера"});
    }
});

app.post("/api/set/messages/is/readed/:groupId", authMiddleware, async (req, res)=>{
    try {
        console.log("Зашли в запрос обновления непрочитаннных");
        const userId = req.user.id;
        const groupId = req.params.groupId;
        const setData = await connection.promise().query(`
            UPDATE messages_views SET is_viewed = ?
                WHERE user_id = ? AND group_id = ?
        `, [1, userId, groupId]);
        res.status(200).json({message: "readed messages is UPDATED"});
        
    } catch (error) {
        console.log(error);
        res.status(500).json({message: `${error}`});
    }
});

// ДОБАВИТЬ ИСТОРИЮ
app.post("/api/add/history", authMiddleware, upload.single("file"), async (req, res)=>{
    const video = req["file"];
    const historyPath = "http://localhost:3001" + "/uploads/" + video.filename;
    const userId = req.user.id;
    try {
        const result = await connection.promise().query(`
            INSERT INTO histories(user_id, history_path) VALUES (?, ?)
        `, [userId, historyPath]);
        res.status(200).json({message: "Adding history successfully"});
    }
    catch (error) {
        res.status(500).json({message: `${error}`});
    }

});

// ПОЛУЧИТЬ ВСЕ ИСТОРИИ ЗНАКОМЫХ
app.get("/api/histories", authMiddleware, async (req, res)=>{
    // const userId = req.user.id;
    const userId = 5;
    try {
        const [histories] = await connection.promise().query(`
            SELECT h.history_path, u.user_initials FROM histories h
                INNER JOIN users u ON u.user_id = h.user_id AND u.is_deleted = 0
                INNER JOIN group_members gm ON gm.user_id = u.user_id
                INNER JOIN groups_table gt ON gt.group_id = gm.group_id AND gt.is_private = 1 AND gt.is_personal = 1
            WHERE gm.group_id IN
                  (
                      SELECT group_id FROM group_members gm WHERE user_id = ?
                  )
            AND gm.user_id <> ?
        `, [userId, userId])
        res.status(200).json({histories: histories});
    }
    catch(error){
        res.status(500).json({message: `${error}`});
    }
});

server.listen(PORT, () => {
    console.log(`Сервер работает на http://localhost:${PORT}`);
})
