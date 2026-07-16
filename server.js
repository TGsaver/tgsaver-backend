// server.js - Backend server for Telegram Saver v3.4.0 (Heleket Edition)
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch'); // npm install node-fetch@2
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 5000;
const DB_FILE = path.join(__dirname, 'users.json');

// Настройки Heleket для приёма платежей (без ИП, принимают РФ и СНГ)
// Замените на ваши ключи после регистрации в личном кабинете на heleket.com
const HELEKET_MERCHANT_UUID = process.env.HELEKET_MERCHANT_UUID || '5d8b1017-f6b4-45d4-b9a9-5ecb0f839665';
const HELEKET_API_KEY = process.env.HELEKET_API_KEY || 'YOUR_HELEKET_API_KEY';
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID || '1058038592594-pt2l6tjbapqvolcb2qeapmbm5bdv9er4.apps.googleusercontent.com';

app.use(cors({
  origin: [
    'https://tgsaver.github.io',
    'http://localhost:3000',
    /^chrome-extension:\/\//
  ],
  credentials: true
}));
app.use(bodyParser.json());

// Лимиты тарифных планов
const PLANS = {
  free: { media: 5, text: 10, label: 'Free' },
  light: { media: 20, text: 40, label: 'Light' },
  pro: { media: 100, text: 200, label: 'Pro' },
  unlimited: { media: Infinity, text: Infinity, label: 'Unlimited' }
};

// Загрузка / инициализация локальной БД
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }, null, 2));
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE));
  } catch (e) {
    return { users: {} };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Помощник для проверки сброса лимитов
function checkAndResetLimits(user) {
  const now = Date.now();
  const resetInterval = user.plan === 'free' ? 3 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;

  if (now > user.limitReset) {
    user.mediaUsed = 0;
    user.textUsed = 0;
    user.limitReset = now + resetInterval;
    return true;
  }
  return false;
}

// Генерация цифровой подписи Heleket (MD5 от Base64 тела запроса + API Key)
function generateHeleketSignature(body, apiKey) {
  const base64Body = Buffer.from(JSON.stringify(body)).toString('base64');
  return crypto.createHash('md5').update(base64Body + apiKey).digest('hex');
}

// ═══ API ENDPOINTS ═══

// 1. Авторизация через Google OAuth Token
app.post('/api/auth/google', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) {
    return res.status(400).json({ error: 'Access token is required' });
  }

  try {
    const googleRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!googleRes.ok) {
      return res.status(401).json({ error: 'Invalid Google Token' });
    }

    const profile = await googleRes.json();
    const db = readDB();

    if (!db.users[profile.id]) {
      db.users[profile.id] = {
        id: profile.id,
        email: profile.email,
        name: profile.name || 'Пользователь',
        picture: profile.picture || '',
        plan: 'free',
        mediaUsed: 0,
        textUsed: 0,
        limitReset: Date.now() + (3 * 24 * 60 * 60 * 1000)
      };
    } else {
      db.users[profile.id].name = profile.name || db.users[profile.id].name;
      db.users[profile.id].picture = profile.picture || db.users[profile.id].picture;
    }

    const user = db.users[profile.id];
    checkAndResetLimits(user);
    writeDB(db);

    res.json({ success: true, user });
  } catch (error) {
    console.error('Google Auth Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 1b. Авторизация через Google ID Token (для веб-сайта)
app.post('/api/auth/google-web', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ error: 'ID token is required' });

  try {
    const client = new OAuth2Client(GOOGLE_WEB_CLIENT_ID);
    let payload;

    try {
      // Пробуем верифицировать с audience
      const ticket = await client.verifyIdToken({
        idToken,
        audience: GOOGLE_WEB_CLIENT_ID
      });
      payload = ticket.getPayload();
    } catch (audienceErr) {
      console.warn('Audience check failed, retrying without:', audienceErr.message);
      // Фоллбэк — верифицируем без проверки audience
      const ticket = await client.verifyIdToken({ idToken });
      payload = ticket.getPayload();
    }

    const db = readDB();
    const userId = payload.sub;

    if (!db.users[userId]) {
      db.users[userId] = {
        id: userId,
        email: payload.email,
        name: payload.name || 'User',
        picture: payload.picture || '',
        plan: 'free',
        mediaUsed: 0,
        textUsed: 0,
        limitReset: Date.now() + (3 * 24 * 60 * 60 * 1000)
      };
    } else {
      db.users[userId].name = payload.name || db.users[userId].name;
      db.users[userId].picture = payload.picture || db.users[userId].picture;
    }

    const user = db.users[userId];
    checkAndResetLimits(user);
    writeDB(db);

    res.json({ success: true, user, sessionToken: userId });
  } catch (error) {
    console.error('Google Web Auth Error:', error.message);
    res.status(401).json({ error: 'Invalid ID Token' });
  }
});

// 2. Получить текущие лимиты
app.get('/api/user/limits', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const googleRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!googleRes.ok) return res.status(401).json({ error: 'Invalid Session' });

    const profile = await googleRes.json();
    const db = readDB();
    const user = db.users[profile.id];

    if (!user) return res.status(404).json({ error: 'User not found' });

    checkAndResetLimits(user);
    writeDB(db);

    res.json({
      plan: user.plan,
      mediaUsed: user.mediaUsed,
      mediaMax: PLANS[user.plan].media,
      textUsed: user.textUsed,
      textMax: PLANS[user.plan].text,
      limitReset: user.limitReset
    });
  } catch (e) {
    res.status(500).json({ error: 'Server Error' });
  }
});

// 2b. Получить лимиты по userId (для веб-сайта)
app.get('/api/user/limits-by-id', (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: 'userId is required' });

  const db = readDB();
  const user = db.users[userId];
  if (!user) return res.status(404).json({ error: 'User not found' });

  checkAndResetLimits(user);
  writeDB(db);

  const planLimits = PLANS[user.plan];
  res.json({
    plan: user.plan,
    mediaUsed: user.mediaUsed,
    textUsed: user.textUsed,
    mediaMax: planLimits.media === Infinity ? null : planLimits.media,
    textMax: planLimits.text === Infinity ? null : planLimits.text,
    limitReset: user.limitReset
  });
});

// 3. Зафиксировать действие и списать лимит
app.post('/api/user/track-action', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { actionType } = req.body;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const googleRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!googleRes.ok) return res.status(401).json({ error: 'Invalid Session' });

    const profile = await googleRes.json();
    const db = readDB();
    const user = db.users[profile.id];

    if (!user) return res.status(404).json({ error: 'User not found' });

    checkAndResetLimits(user);

    const planLimits = PLANS[user.plan];
    if (actionType === 'media') {
      if (user.mediaUsed >= planLimits.media) {
        return res.status(429).json({ error: 'Limit exceeded', limitType: 'media' });
      }
      user.mediaUsed++;
    } else {
      if (user.textUsed >= planLimits.text) {
        return res.status(429).json({ error: 'Limit exceeded', limitType: 'text' });
      }
      user.textUsed++;
    }

    writeDB(db);
    res.json({
      success: true,
      mediaUsed: user.mediaUsed,
      mediaMax: planLimits.media,
      textUsed: user.textUsed,
      textMax: planLimits.text
    });
  } catch (e) {
    res.status(500).json({ error: 'Server Error' });
  }
});

// 4. Локальная ручная активация тарифа
app.post('/api/payments/mock-activate', async (req, res) => {
  const { email, plan } = req.body;
  if (!email || !plan || !PLANS[plan]) {
    return res.status(400).json({ error: 'Invalid email or plan' });
  }

  const db = readDB();
  let foundUser = null;

  for (const id in db.users) {
    if (db.users[id].email.toLowerCase() === email.toLowerCase()) {
      foundUser = db.users[id];
      break;
    }
  }

  if (!foundUser) {
    return res.status(404).json({ error: 'User with this email not registered yet' });
  }

  foundUser.plan = plan;
  foundUser.mediaUsed = 0;
  foundUser.textUsed = 0;
  foundUser.limitReset = Date.now() + (plan === 'free' ? 3 : 1) * 24 * 60 * 60 * 1000;

  writeDB(db);
  res.json({ success: true, message: `Successfully upgraded ${email} to ${plan.toUpperCase()}` });
});

// 5. Создание счета Heleket (или перенаправление на локальный симулятор)
app.post('/api/payments/create-invoice', async (req, res) => {
  const { email, plan } = req.body;
  if (!email || !plan || !PLANS[plan]) {
    return res.status(400).json({ error: 'Invalid email or plan' });
  }

  const prices = { light: '4.99', pro: '9.99', unlimited: '15.99' };
  const amount = prices[plan];

  // Если API-ключи не настроены — перенаправляем на локальный симулятор
  if (HELEKET_MERCHANT_UUID === 'YOUR_HELEKET_MERCHANT_UUID' || HELEKET_API_KEY === 'YOUR_HELEKET_API_KEY') {
    return res.json({
      success: true,
      payUrl: `http://localhost:${PORT}/api/payments/mock-checkout-page?email=${encodeURIComponent(email)}&plan=${plan}`
    });
  }

  // Если ключи настроены — создаем реальный счет через Heleket API
  try {
    const orderId = `order_${Date.now()}_${email.replace(/[^a-zA-Z0-9]/g, '')}_${plan}`;
    const requestBody = {
      amount: amount,
      currency: 'USD',
      order_id: orderId,
      url_callback: `https://tgsaver-backend.onrender.com/api/payments/heleket-webhook`, // вебхук для получения статуса оплаты
      url_return: 'https://web.telegram.org/a/'
    };

    const signature = generateHeleketSignature(requestBody, HELEKET_API_KEY);

    const apiRes = await fetch('https://api.heleket.com/v1/payment', {
      method: 'POST',
      headers: {
        'merchant': HELEKET_MERCHANT_UUID,
        'sign': signature,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    const data = await apiRes.json();
    
    if (data.state === 0 && data.result && data.result.url) {
      res.json({ success: true, payUrl: data.result.url });
    } else {
      res.status(400).json({ error: data.message || 'Heleket API Error' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate crypto invoice: ' + error.message });
  }
});

// 6. Красивый симулятор оплаты в браузере (для тестов локально)
app.get('/api/payments/mock-checkout-page', (req, res) => {
  const { email, plan } = req.query;
  const prices = { light: '$4.99', pro: '$9.99', unlimited: '$15.99' };
  const price = prices[plan] || 'Unknown';

  res.send(`
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="UTF-8">
      <title>Оплата Heleket (Симулятор)</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Outfit:wght@700;800&display=swap" rel="stylesheet">
      <style>
        body { background-color: #090d16; color: #f8fafc; font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .checkout-card { width: 380px; background: rgba(20, 29, 47, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 20px; padding: 30px; text-align: center; box-shadow: 0 10px 40px rgba(0,0,0,0.5); backdrop-filter: blur(8px); }
        h2 { font-family: 'Outfit', sans-serif; font-size: 24px; margin-bottom: 5px; background: linear-gradient(135deg, #00b4db, #00f2fe); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 25px; }
        .details { background: rgba(255,255,255,0.03); border-radius: 12px; padding: 16px; margin-bottom: 25px; text-align: left; border: 1px solid rgba(255,255,255,0.03); }
        .row { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 14px; }
        .row:last-child { margin-bottom: 0; }
        .label { color: #64748b; }
        .val { font-weight: 600; }
        .price { font-size: 20px; color: #00f2fe; font-weight: 800; }
        .pay-btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #00b4db, #00f2fe); color: #000; border: none; border-radius: 12px; font-weight: 700; font-size: 15px; cursor: pointer; transition: all 0.2s ease; }
        .pay-btn:hover { box-shadow: 0 0 20px rgba(0, 242, 254, 0.4); transform: translateY(-1px); }
      </style>
    </head>
    <body>
      <div class="checkout-card">
        <h2>🪙 Heleket API</h2>
        <p class="subtitle">Инвойс оплаты в криптовалюте (Тестовый симулятор)</p>
        <div class="details">
          <div class="row">
            <span class="label">Аккаунт:</span>
            <span class="val">${email}</span>
          </div>
          <div class="row">
            <span class="label">Тариф:</span>
            <span class="val">${plan.toUpperCase()}</span>
          </div>
          <div class="row" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.06);">
            <span class="label" style="font-size:16px; display:flex; align-items:center;">Сумма к оплате:</span>
            <span class="val price">${price}</span>
          </div>
        </div>
        <button class="pay-btn" onclick="pay()">Оплатить тестовым платежом</button>
      </div>

      <script>
        function pay() {
          const btn = document.querySelector('.pay-btn');
          btn.textContent = 'Обработка транзакции...';
          btn.disabled = true;

          fetch('/api/payments/mock-activate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: '${email}', plan: '${plan}' })
          })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              document.body.innerHTML = \`
                <div class="checkout-card">
                  <h2 style="color:#10b981; background: none; -webkit-text-fill-color: #10b981;">🎉 Успешно оплачено!</h2>
                  <p class="subtitle" style="margin-top: 15px; margin-bottom:0; font-size:14px; line-height:1.6; color:#94a3b8;">
                    Счет успешно оплачен. <br>
                    Тариф повышен до <b>\${'${plan}'.toUpperCase()}</b>.<br><br>
                    Можете закрыть эту вкладку и вернуться в расширение.
                  </p>
                </div>
              \`;
            } else {
              alert('Ошибка оплаты: ' + data.error);
              btn.textContent = 'Оплатить тестовым платежом';
              btn.disabled = false;
            }
          })
          .catch(err => {
            alert('Ошибка сети: ' + err.message);
            btn.textContent = 'Оплатить тестовым платежом';
            btn.disabled = false;
          });
        }
      </script>
    </body>
    </html>
  `);
});

// 7. Реальный вебхук от Heleket для автоактиваций
app.post('/api/payments/heleket-webhook', (req, res) => {
  const { sign, status, order_id } = req.body;
  
  if (!sign) return res.status(400).send('No sign provided');

  // Верификация подписи Heleket
  const body = { ...req.body };
  delete body.sign;

  const calculatedSign = generateHeleketSignature(body, HELEKET_API_KEY);
  if (calculatedSign !== sign) {
    console.warn('[Heleket Webhook] Sign verification FAILED');
    return res.status(400).send('Invalid signature');
  }

  if (status === 'success' || status === 'paid') {
    const parts = order_id.split('_');
    const email = parts[2];
    const plan = parts[3];

    if (email && plan) {
      const db = readDB();
      let foundUser = null;

      for (const id in db.users) {
        if (db.users[id].email.toLowerCase() === email.toLowerCase()) {
          foundUser = db.users[id];
          break;
        }
      }

      if (foundUser) {
        foundUser.plan = plan;
        foundUser.mediaUsed = 0;
        foundUser.textUsed = 0;
        foundUser.limitReset = Date.now() + 24 * 60 * 60 * 1000;
        
        writeDB(db);
        console.log(`[TG Saver Server] Heleket SUCCESS: user ${email} upgraded to ${plan.toUpperCase()}`);
      }
    }
  }

  res.send('OK');
});

app.listen(PORT, () => {
  console.log(`[TG Saver Server] Running on port ${PORT}`);
});
