const { PlayIntegrity } = require('@google-cloud/playintegrity');
const Buffer = require('buffer').Buffer;

// Khởi tạo biến toàn cục
let playIntegrityClient;
let cloudProjectNumber;
let serverApiKey;

// Hàm khởi tạo Client Google (Chỉ chạy một lần trong quá trình khởi động Function)
function initializeClient() {
    if (playIntegrityClient) return;

    // Đọc hai biến môi trường quan trọng từ Netlify
    const base64Key = process.env.SERVICE_ACCOUNT_KEY_JSON_BASE64;
    serverApiKey = process.env.API_KEY;

    if (!base64Key || !serverApiKey) {
        throw new Error("Missing SERVICE_ACCOUNT_KEY_JSON_BASE64 or API_KEY environment variables.");
    }
    
    try {
        // Giải mã JSON Key từ BASE64
        const keyJson = Buffer.from(base64Key, 'base64').toString('utf8');
        const credentials = JSON.parse(keyJson);
        
        playIntegrityClient = new PlayIntegrity({ credentials });
        // Lấy Cloud Project Number
        cloudProjectNumber = credentials.project_id.match(/\d+/)?.[0] || process.env.CLOUD_PROJECT_NUMBER;
        
        console.log("Client initialized successfully.");
    } catch (error) {
        console.error("ERROR: Failed to initialize Play Integrity Client:", error.message);
        throw new Error("Invalid Service Account Key configuration.");
    }
}

// --- Netlify Handler (Điểm khởi chạy chính) ---
exports.handler = async (event, context) => {
    // Chỉ xử lý POST request
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ message: "Method Not Allowed" }) };
    }

    try {
        // Khởi tạo client 
        initializeClient();

        // --- 1. Xác thực API Key (từ header x-api-key gửi từ Godot) ---
        const apiKey = event.headers['x-api-key'];
        if (!apiKey || apiKey !== serverApiKey) {
            console.warn(`[ATTENTION] Unauthorized access attempt with key: ${apiKey}`);
            return { 
                statusCode: 401, 
                body: JSON.stringify({ success: false, message: 'Unauthorized: Invalid X-API-KEY' }) 
            };
        }

        // --- 2. Lấy body (token và nonce) ---
        const body = JSON.parse(event.body);
        const { token, nonce } = body;

        if (!token || !nonce) {
            return { 
                statusCode: 400, 
                body: JSON.stringify({ success: false, message: 'Bad Request: Missing token or nonce.' }) 
            };
        }

        console.log(`\n[REQUEST] Verifying token for nonce: ${nonce}`);

        // --- 3. Gọi Google Play Integrity API ---
        const response = await playIntegrityClient.decodeIntegrityToken({
            integrityToken: token,
            cloudProjectNumber: cloudProjectNumber
        });

        const tokenPayload = response.tokenPayload;
        const appIntegrity = tokenPayload.appIntegrity;
        const deviceIntegrity = tokenPayload.deviceIntegrity;
        
        // --- 4. Kiểm tra Nonce (chống Replay Attack) ---
        if (tokenPayload.requestDetails.nonce !== nonce) {
             console.warn(`[VERIFICATION FAILED] Nonce mismatch. Expected: ${nonce}, Received: ${tokenPayload.requestDetails.nonce}`);
             return {
                 statusCode: 200, 
                 body: JSON.stringify({
                    success: true, 
                    valid: false, 
                    message: "Integrity check failed: Nonce mismatch (Replay Attack possible)",
                    details: { nonce_match: false, app_integrity: appIntegrity, device_integrity: deviceIntegrity }
                 })
             };
        }

        // --- 5. LOGIC XÁC MINH CƠ BẢN ---
        
        // Kiểm tra ứng dụng được cấp phép
        const appVerdict = appIntegrity.appLicensingVerdict;
        const appIsLicensed = (appVerdict === 'LICENSED' || appVerdict === 'UNLICENSED');
        
        // Kiểm tra Tính toàn vẹn cơ bản của thiết bị
        const meetsBasicIntegrity = deviceIntegrity.integrityVerdict.includes('BASIC_INTEGRITY');

        const isValid = meetsBasicIntegrity && appIsLicensed;

        const details = {
            request_nonce: tokenPayload.requestDetails.nonce,
            meets_basic_integrity: meetsBasicIntegrity,
            app_is_licensed: appIsLicensed,
            final_verdict: isValid ? 'VALID_DEVICE_AND_LICENSED' : 'CHECK_FAILED',
        };
        
        console.log(`[VERIFICATION RESULT] Nonce Match: TRUE. Final Verdict: ${details.final_verdict}`);

        // --- 6. Trả về kết quả ---
        return {
            statusCode: 200,
            body: JSON.stringify({
                success: true,
                valid: isValid,
                message: isValid ? 'Integrity check passed.' : 'Integrity check failed.',
                details: details
            })
        };

    } catch (error) {
        console.error("[GOOGLE API ERROR] Failed to decode token:", error.message);
        return { 
            statusCode: 500, 
            body: JSON.stringify({ 
                success: false, 
                message: 'Internal Server Error: Failed to communicate with Google API.', 
                error: error.message 
            }) 
        };
    }
};
