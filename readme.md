# Simulacro de Incidente de Brecha de Datos

## Descripción
Aplicación de demostración para simular un incidente de seguridad con intentos de acceso no autorizados.

## Mejoras de Seguridad Recomendadas

### 1. Bloqueo Automático de IPs

Para bloquear IPs que realicen múltiples intentos fallidos, deberías implementar:

```javascript
// En server.js
const failedAttempts = {}; // Almacena intentos fallidos por IP
const blockedIPs = new Set(); // IPs bloqueadas
const MAX_ATTEMPTS = 5; // Máximo de intentos permitidos
const BLOCK_DURATION = 15 * 60 * 1000; // 15 minutos en milisegundos

// Middleware para verificar IPs bloqueadas
app.use((req, res, next) => {
  const ip = req.ip;
  if (blockedIPs.has(ip)) {
    logEvent('BLOCKED_ACCESS_ATTEMPT', 'N/A', ip);
    return res.status(403).json({ error: 'IP bloqueada temporalmente' });
  }
  next();
});

// En el endpoint de login, después de un fallo:
app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  const ip = req.ip;

  if (users[user] && users[user] === pass) {
    // Reiniciar contador en caso de éxito
    failedAttempts[ip] = 0;
    logEvent('LOGIN_SUCCESS', user, ip);
    res.sendStatus(200);
  } else {
    // Incrementar intentos fallidos
    failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;
    logEvent('LOGIN_FAIL', user, ip);
    
    // Bloquear si se excede el límite
    if (failedAttempts[ip] >= MAX_ATTEMPTS) {
      blockedIPs.add(ip);
      logEvent('IP_BLOCKED', user, ip);
      
      // Desbloquear después del tiempo establecido
      setTimeout(() => {
        blockedIPs.delete(ip);
        failedAttempts[ip] = 0;
        logEvent('IP_UNBLOCKED', 'N/A', ip);
      }, BLOCK_DURATION);
      
      return res.status(403).json({ error: 'IP bloqueada por múltiples intentos fallidos' });
    }
    
    res.sendStatus(401);
  }
});
```

### 2. Detección Automática de Accesos Fallidos

Para monitorear y detectar patrones sospechosos automáticamente:

```javascript
// Monitoreo en tiempo real de intentos fallidos
function monitorFailedAttempts() {
  setInterval(() => {
    const now = Date.now();
    
    for (const [ip, attempts] of Object.entries(failedAttempts)) {
      if (attempts >= 3 && attempts < MAX_ATTEMPTS) {
        console.warn(`⚠️  ALERTA: IP ${ip} tiene ${attempts} intentos fallidos`);
        logEvent('SUSPICIOUS_ACTIVITY', 'N/A', ip);
      }
    }
  }, 30000); // Revisar cada 30 segundos
}

// Analizar el log de seguridad
function analyzeSecurityLog() {
  const log = fs.readFileSync('security.log', 'utf8');
  const lines = log.split('\n').filter(line => line.includes('LOGIN_FAIL'));
  
  const ipMap = {};
  lines.forEach(line => {
    const ipMatch = line.match(/ip=([^\s]+)/);
    if (ipMatch) {
      const ip = ipMatch[1];
      ipMap[ip] = (ipMap[ip] || 0) + 1;
    }
  });
  
  // Reportar IPs con alto número de fallos
  for (const [ip, count] of Object.entries(ipMap)) {
    if (count >= 10) {
      console.error(`🚨 IP SOSPECHOSA: ${ip} con ${count} intentos fallidos totales`);
    }
  }
}

// Iniciar en el servidor
monitorFailedAttempts();
```

### 3. Otras Mejoras de Seguridad

- **Rate Limiting**: Usar `express-rate-limit` para limitar peticiones por IP
- **Almacenamiento de contraseñas**: Usar `bcrypt` para hashear contraseñas
- **Registro detallado**: Guardar timestamp, user-agent, y otros metadatos
- **Alertas**: Enviar notificaciones cuando se detecten patrones sospechosos
- **Análisis de logs**: Implementar herramientas como fail2ban para análisis automático

## Instalación

```bash
npm install express
node server.js
```

## Uso

Abre `index.html` en tu navegador y prueba las funciones de registro y login.

