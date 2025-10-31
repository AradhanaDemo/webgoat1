package org.owasp.webgoat.security.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.owasp.webgoat.session.WebSession;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/mfa")
public class MfaController implements InitializingBean {

    @Autowired
    private WebSession webSession;

    private MfaService mfaService;

    @Override
    public void afterPropertiesSet() {
        // Issuer as shown in Microsoft Authenticator
        this.mfaService = new MfaService("WebGoat");
    }

    @PostMapping(path = "/setup", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> setup() {
        String user = webSession.getUserName();
        var rec = mfaService.initForUser(user);
        String secret = mfaService.getBase32Secret(rec.getSecret());
        String otpauth = mfaService.buildOtpAuthUri(user, rec.getSecret());

        Map<String, Object> resp = new HashMap<>();
        resp.put("secret", secret);
        resp.put("otpauthUri", otpauth);
        resp.put("enabled", rec.isEnabled());
        return resp;
    }

    @GetMapping(path = "/qr", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qr() throws IOException, WriterException {
        String user = webSession.getUserName();
        var rec = mfaService.getRecord(user);
        if (rec == null) return ResponseEntity.notFound().build();
        String otpauth = mfaService.buildOtpAuthUri(user, rec.getSecret());

        byte[] image = generateQrPng(otpauth, 280, 280);
        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_PNG)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(image);
    }

    @PostMapping(path = "/enable", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> enable(@RequestBody Map<String, String> body) {
        String code = body == null ? null : body.get("code");
        String user = webSession.getUserName();
        var rec = mfaService.getRecord(user);
        if (rec == null) return ResponseEntity.badRequest().body(Map.of("error", "MFA not initialized. Call /mfa/setup first."));

        boolean ok = mfaService.verifyCode(rec.getSecret(), code);
        if (ok) {
            mfaService.enable(user);
            return ResponseEntity.ok(Map.of("enabled", true));
        }
        return ResponseEntity.status(401).body(Map.of("enabled", false, "error", "Invalid code"));
    }

    @PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> verify(@RequestBody Map<String, String> body) {
        String code = body == null ? null : body.get("code");
        String user = webSession.getUserName();
        var rec = mfaService.getRecord(user);
        if (rec == null || !rec.isEnabled()) return ResponseEntity.status(403).body(Map.of("verified", false, "error", "MFA not enabled"));

        boolean ok = mfaService.verifyCode(rec.getSecret(), code);
        if (ok) {
            return ResponseEntity.ok(Map.of("verified", true));
        }
        return ResponseEntity.status(401).body(Map.of("verified", false, "error", "Invalid code"));
    }

    private byte[] generateQrPng(String contents, int width, int height) throws IOException, WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(contents, BarcodeFormat.QR_CODE, width, height);
        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        return pngOutputStream.toByteArray();
    }
}
