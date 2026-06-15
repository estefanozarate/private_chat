# Fase 0 + Fase 1 — notas de implementación

Estado: **entregado**. Cubre setup ESP-IDF + protocolo serial TLV (firmware
ESP-IDF para ESP32-S3 y cliente Web Serial en JS). El protocolo de cable
(CRC16 + framing) está verificado byte-a-byte entre C y JS.

---

## Decisiones de diseño (y desviaciones del plan original)

Cinco cosas del plan tenían huecos o contradicciones técnicas. Las cerré así;
revísalas porque algunas cambian garantías de seguridad.

### 1. AEAD = AES-256-GCM, **no** ChaCha20-Poly1305
El plan dice "ChaCha20-Poly1305 vía WebCrypto" (Fase 3). **WebCrypto no soporta
ChaCha20-Poly1305** — solo AES-GCM entre los AEAD. Para que el device (Diseño A)
y el browser (Diseño B) sean interoperables con `crypto.subtle`, todo usa
**AES-256-GCM con nonce de 12 bytes**. En firmware uso mbedTLS (acelerado por
hardware en el S3). Si insistes en ChaCha20-Poly1305, el browser necesitaría una
lib WASM (libsodium.js / noble-ciphers), no WebCrypto — dímelo y lo cambio.

### 2. Stack cripto: Monocypher + mbedTLS (no uno solo)
- **X25519 + Ed25519**: Monocypher (vendored). mbedTLS **no** trae Ed25519.
- **AES-GCM + HKDF-SHA256 + RNG**: mbedTLS / ESP-IDF.
- Ed25519: uso el add-on `monocypher-ed25519` (**RFC 8032 / SHA-512**), no el
  `crypto_eddsa_*` por defecto de Monocypher, que usa BLAKE2b y **no es
  verificable** por WebCrypto Ed25519 ni noble-ed25519. Esto importa si la firma
  de `SIGN_CHALLENGE` se valida fuera de otro ESP32.

### 3. Frame con preámbulo SOF `0xA5 0x5A`
El frame del plan no tenía marcador de inicio: un stream serial sin SOF no puede
resincronizar tras un byte perdido o corrupción. Agregué 2 bytes de SOF (fuera
del CRC). El parser es una máquina de estados que vuelve a "buscar SOF" tras
cualquier CRC inválido. Verificado: descarta frames corruptos y se recupera en
el siguiente frame válido.

### 4. `GET_PUBKEY` devuelve 64 bytes (X25519 || Ed25519)
El plan decía 32 bytes (solo X25519). Pero `SIGN_CHALLENGE` produce firma
Ed25519 y el verificador necesita la pubkey Ed25519 — que no se exponía en
ningún comando. Por eso `GET_PUBKEY` ahora devuelve `x25519_pub(32) ||
ed25519_pub(32)`.

### 5. `DERIVE_SESSION` devuelve **dos** claves direccionales (64 bytes)
Éste es el cambio importante de seguridad. Si ambos peers comparten **una sola**
`session_key` y ambos cifran con AES-GCM, van a reusar nonces bajo la misma clave
(empiezan el contador en 0) → **rotura catastrófica de GCM** (recuperación del
authentication key + XOR de plaintexts). Solución estándar: claves
**direccionales**. De `shared = X25519(...)` derivo vía HKDF dos claves ligadas a
ambas pubkeys ordenadas:

```
k_l2h = HKDF(shared, "chat-e2e/v1/l2h" || low_pk || high_pk)
k_h2l = HKDF(shared, "chat-e2e/v1/h2l" || low_pk || high_pk)
```

El device se asigna `send`/`recv` según su rol (quién tiene la pubkey
lexicográficamente menor), garantizando `A.send == B.recv`. `DERIVE_SESSION`
exporta `send_key(32) || recv_key(32)`.

> **Caveat de modelo de amenaza** (importante): en Diseño B la clave de sesión
> *sí sale* del HSM (se exporta al browser para que WebCrypto cifre). El
> invariante "las claves nunca salen del ESP32" aplica solo a las claves
> **privadas de identidad** (X25519/Ed25519), no a las claves de sesión. Si
> quieres que NUNCA salga ninguna clave, hay que usar Diseño A (todo mensaje
> pasa por el ESP32 vía `ENCRYPT`/`DECRYPT`) — pero eso limita throughput al
> round-trip USB por mensaje y desgasta consideraciones de nonce. Ambos caminos
> están implementados; la decisión es de Fase 3.

---

## Otras notas técnicas

- **Nonce**: `gen(4 LE) || counter(8 LE)` = 12 bytes. El contador vive **en RAM**,
  no en NVS (escribir flash por mensaje lo desgastaría). Se reinicia a 0 en cada
  cambio de clave (derive / ratchet), lo cual es seguro porque clave nueva ⇒
  par (nonce, key) nunca repetido.
- **Ratchet simple**: avance KDF unidireccional de ambas cadenas
  (`new = HKDF(old, "ratchet")`), `gen++`. Da forward secrecy pero **no**
  post-compromise security (no hay DH nuevo). Double Ratchet completo = Fase 7,
  como dice el plan.
- **RNG**: este HSM no usa WiFi/BT, así que el RNG de hardware no está sembrado
  por RF. En provisioning llamo `bootloader_random_enable()` antes de generar
  claves y lo deshabilito después.
- **DERIVE_SESSION** usa la clave X25519 de **identidad** (no efímera) en v1.
  El handshake efímero (estilo X3DH) es decisión de Fase 3 — el plan lo deja
  explícitamente abierto. Con identidad fija pierdes forward secrecy en el
  establecimiento (el ratchet la recupera con el tiempo).
- **Claves en reposo**: NVS cifrado (`CONFIG_NVS_ENCRYPTION`) sobre flash
  encryption. Nota honesta: el ESP32-S3 **no es un secure element**; con acceso
  físico y decapping no es a prueba de manipulación. Para tu modelo de "MiniHSM"
  es aceptable, pero conviene tenerlo escrito.

---

## Comandos implementados (Fase 1)

| CMD  | Request                       | Response                                  |
|------|-------------------------------|-------------------------------------------|
| 0x01 | (vacío)                       | x25519_pub(32) ‖ ed25519_pub(32)          |
| 0x02 | peer_x25519_pub(32)           | send_key(32) ‖ recv_key(32)               |
| 0x03 | plaintext                     | nonce(12) ‖ ciphertext ‖ tag(16)          |
| 0x04 | nonce(12) ‖ ciphertext ‖ tag  | plaintext                                 |
| 0x05 | (vacío)                       | nuevo gen (uint32 LE)                     |
| 0x06 | challenge                     | firma Ed25519 (64)                        |
| 0xFF | —                             | (response de error: status en byte FLAGS) |

---

## Build & flash

```bash
# 1. Vendorizar Monocypher (una vez)
./firmware/components/monocypher/fetch.sh

# 2. Compilar / flashear
cd firmware
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor   # console por UART; CDC = canal de datos
```

- Pines USB nativos del S3: **GPIO19 (D-)** y **GPIO20 (D+)**.
- La consola/log sale por **UART0**, separada del CDC de datos a propósito.
- Flash encryption viene en modo **DEVELOPMENT**. Para producción: cambiar a
  `RELEASE` y quemar eFuses (irreversible — leer docs de Espressif antes).

## Web

`web/demo.html` + `web/hsm-serial.js`. Servir por HTTPS o `localhost` (Web
Serial lo exige) y abrir en Chrome/Edge:

```bash
cd web && python3 -m http.server 8000   # http://localhost:8000/demo.html
```

`hsm-serial.js` es un módulo ES reutilizable (no depende del demo): clase
`HsmSerial` con cola single-flight + timeout, codec TLV idéntico al firmware, y
helpers WebCrypto (`importSessionKey` como CryptoKey **no extraíble**,
`aeadEncrypt/Decrypt`, `makeNonce`).

---

## Para confirmar antes de avanzar a Fase 2

1. ¿OK con **AES-256-GCM** (descarta ChaCha20-Poly1305 del plan)?
2. ¿OK con `DERIVE_SESSION` exportando **dos claves direccionales** y con que la
   clave de sesión salga del HSM (Diseño B)? ¿O prefieres forzar Diseño A?
3. ¿`DERIVE_SESSION` con clave de **identidad** en v1, o ya quieres efímeras
   (añade un comando `GEN_EPHEMERAL` 0x07)?
4. ¿Multi-sesión? Fase 1 tiene **un solo slot** de sesión. Para varios contactos
   simultáneos hay que indexar por `session_id`.

> No verifiqué en hardware (no tengo ESP32 ni toolchain ESP-IDF aquí). Lo que sí
> está verificado en máquina: CRC16, encoding y el parser/decoder C↔JS
> byte-a-byte. Marca cualquier ajuste tras el primer flash.
