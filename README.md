# Cryptographic Classroom Voting System

Prototipo de votación electrónica de aula con cifrado ElGamal homomórfico y pruebas NIZK de validez de voto (protocolo sigma OR + Fiat–Shamir). Implementado en FastAPI y completamente containerizado con Docker.

---

## Requisitos previos

Solo necesitas tener instalado:

- [Docker](https://docs.docker.com/get-docker/) (versión 20.10 o superior)

No se requiere Python, pip ni ninguna otra dependencia local.

---

## Estructura del proyecto

```
.
├── Dockerfile
├── requirements.txt
├── app/
│   ├── crypto.py       # ElGamal, NIZK, SHA-256 Fiat–Shamir, descifrado
│   ├── database.py     # Estado en memoria, acumulador homomórfico, tokens
│   ├── main.py         # API FastAPI, endpoints, autenticación admin
│   └── schemas.py      # Modelos Pydantic para validación de requests
├── static/
│   ├── index.html      # Panel del votante
│   ├── admin.html      # Panel de administración
│   ├── app.js          # Lógica cliente y generación de prueba NIZK
│   └── styles.css      # Estilos
└── tests/
    └── test_voting.py  # Suite de pruebas automatizadas (pytest)
```

---

## Inicio rápido

### 1. Construir la imagen

```bash
docker build -t vote-system .
```

### 2. Levantar el contenedor

```bash
docker run --name voting-app -p 8000:8000 -d vote-system
```

El servidor queda corriendo en segundo plano y expone el puerto `8000` en tu máquina local.

### 3. Obtener las credenciales de administrador

Las credenciales se generan aleatoriamente en cada arranque y se imprimen en los logs del contenedor:

```bash
docker logs voting-app
```

Busca el bloque que se ve así:

```
======================================================================
 🛡️  HOMOMORPHIC ELGAMAL VOTING SYSTEM - STARTUP SUCCESSFUL
======================================================================
  ADMIN DASHBOARD LOGIN CREDENTIALS:
    - URL:       http://localhost:8000/admin
    - Username:  admin
    - Password:  <contraseña generada>
======================================================================
```

Guarda la contraseña, la necesitarás para acceder al panel de administración.

### 4. Acceder a los paneles

| Panel | URL | Acceso |
|---|---|---|
| Votante (cliente) | http://localhost:8000/ | Abierto |
| Administración | http://localhost:8000/admin | HTTP Basic Auth |
| Documentación API | http://localhost:8000/docs | Abierto |

---

## Flujo de uso

### Como administrador

1. Accede a `http://localhost:8000/admin` con las credenciales obtenidas en el paso 3.
2. Genera un lote de tokens para los votantes (ej. 10 tokens).
3. Distribuye cada token a un votante.
4. Cuando todos hayan votado, haz clic en **Close Election** para descifrar el agregado y ver el resultado final.
5. Usa **Reset Election** para iniciar una nueva votación con claves frescas.

### Como votante

1. Accede a `http://localhost:8000/`.
2. Ingresa el token que recibiste del administrador.
3. Selecciona tu respuesta (Sí / No).
4. Haz clic en **Submit Vote**.

El panel muestra en tiempo real el estado del acumulador homomórfico y el ledger de transacciones. Puedes expandir el **inspector criptográfico** para ver el cifrado ElGamal y la prueba NIZK generados en tu navegador antes de ser enviados al servidor.

---

## Pruebas automatizadas

La suite cubre seis escenarios: voto válido individual, todos sí, todos no, mixto, ataque de reuso de token y prueba NIZK inválida.

### Ejecutar desde el contenedor en ejecución

```bash
docker exec -it voting-app bash -c "PYTHONPATH=/app pytest tests/test_voting.py -v"
```

### Ejecutar sin levantar el servidor web (contenedor desechable)

```bash
docker run --rm vote-system bash -c "PYTHONPATH=/app pytest tests/test_voting.py -v"
```

### Salida esperada

```
tests/test_voting.py::test_valid_vote_single         PASSED
tests/test_voting.py::test_all_yes_scenario          PASSED
tests/test_voting.py::test_all_no_scenario           PASSED
tests/test_voting.py::test_mixed_scenario            PASSED
tests/test_voting.py::test_token_replay_attack       PASSED
tests/test_voting.py::test_malformed_vote_invalid_nizk PASSED

6 passed in Xs
```

---

## Gestión del contenedor

```bash
# Ver logs en tiempo real
docker logs -f voting-app

# Detener el contenedor
docker stop voting-app

# Eliminar el contenedor
docker rm voting-app

# Reconstruir tras cambios en el código
docker stop voting-app && docker rm voting-app
docker build -t vote-system . && docker run --name voting-app -p 8000:8000 -d vote-system
```

> **Nota:** el estado de la elección vive en memoria dentro del contenedor. Al detener y eliminar el contenedor, todos los votos, tokens y logs se pierden. Esto es intencional en este prototipo de aula.

---

## Variables y configuración

No se requiere ningún archivo `.env`. La única configuración relevante es el puerto expuesto, que puede cambiarse al levantar el contenedor:

```bash
# Usar el puerto 9000 en lugar de 8000
docker run --name voting-app -p 9000:8000 -d vote-system
```

---

## Referencia de la API

La documentación interactiva completa (Swagger UI) está disponible en `http://localhost:8000/docs` una vez que el contenedor está corriendo. Los endpoints principales son:

| Método | Ruta | Acceso | Descripción |
|---|---|---|---|
| GET | `/api/election/parameters` | Público | Parámetros criptográficos `p, q, g, u` |
| GET | `/api/election/state` | Público | Estado del acumulador, tokens y ledger |
| POST | `/api/election/vote` | Público | Emitir un voto cifrado con prueba NIZK |
| POST | `/api/election/tokens` | Admin | Generar tokens de un solo uso |
| POST | `/api/election/close` | Admin | Cerrar elección y descifrar el agregado |
| POST | `/api/election/reset` | Admin | Reiniciar con nuevas claves criptográficas |

---

## Referencias

- Boneh, D. & Shoup, V. — *A Graduate Course in Applied Cryptography*, sección 20.3.1
- Adida, B. (2008) — *Helios: Web-based Open-Audit Voting*, USENIX Security
- RFC 3526 — *More MODP Diffie-Hellman groups for IKE* (Group 14, 2048-bit)
