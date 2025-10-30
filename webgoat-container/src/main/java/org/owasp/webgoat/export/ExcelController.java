package org.owasp.webgoat.export;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.session.WebSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/excel")
public class ExcelController {

    @Autowired
    private WebSession webSession;

    // In-memory store for generated Excel files (id -> file bytes)
    private static final Map<String, byte[]> EXCEL_STORE = new ConcurrentHashMap<>();

    @PostMapping(path = "/create", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> createExcel(@RequestBody(required = false) Map<String, Object> userInput) throws IOException {
        Map<String, Object> data = new LinkedHashMap<>();
        if (userInput != null) {
            data.putAll(userInput);
        }
        // Add sample parameters
        String id = UUID.randomUUID().toString();
        data.put("id", id);
        data.put("user", webSession.getUserName());
        data.put("generatedAt", DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(OffsetDateTime.now()));

        // Create workbook
        byte[] bytes = buildWorkbookBytes(data);
        EXCEL_STORE.put(id, bytes);

        String downloadPath = "/excel/download/" + id;
        Map<String, Object> resp = new HashMap<>();
        resp.put("id", id);
        resp.put("downloadPath", downloadPath);
        return resp;
    }

    @GetMapping(path = "/download/{id}")
    public ResponseEntity<byte[]> downloadExcel(@PathVariable("id") String id) {
        byte[] bytes = EXCEL_STORE.get(id);
        if (bytes == null) {
            return ResponseEntity.notFound().build();
        }
        String filename = "export-" + id + ".xlsx";
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                .body(bytes);
    }

    private byte[] buildWorkbookBytes(Map<String, Object> data) throws IOException {
        try (Workbook workbook = new XSSFWorkbook(); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            Sheet sheet = workbook.createSheet("Data");

            // Header row
            Row header = sheet.createRow(0);
            int col = 0;
            for (String key : data.keySet()) {
                header.createCell(col++).setCellValue(key);
            }

            // Data row
            Row row = sheet.createRow(1);
            col = 0;
            for (Object value : data.values()) {
                row.createCell(col++).setCellValue(value == null ? "" : String.valueOf(value));
            }

            // Autosize columns
            for (int c = 0; c < data.size(); c++) {
                sheet.autoSizeColumn(c);
            }

            workbook.write(bos);
            return bos.toByteArray();
        }
    }
}
