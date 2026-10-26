package shshsb.sbssbab. double;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_PICK = 1001;

    private TextView tvResult;
    private Button btnCopy;
    private String currentResult = "";
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvResult = findViewById(R.id.tvResult);
        btnCopy = findViewById(R.id.btnCopy);
        Button btnPick = findViewById(R.id.btnPick);

        btnPick.setOnClickListener(v -> pickFile());
        btnCopy.setOnClickListener(v -> copyResult());

        // استقبال الملف إذا أُرسل من تطبيق آخر
        Intent intent = getIntent();
        if (intent != null) handleIntent(intent);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        Uri uri = intent.getData();
        if (uri != null) processUri(uri);
    }

    private void pickFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, REQUEST_PICK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_PICK && resultCode == Activity.RESULT_OK && data != null) {
            processUri(data.getData());
        }
    }

    private void processUri(Uri uri) {
        tvResult.setText("⏳ جاري فك التشفير...");
        btnCopy.setEnabled(false);

        executor.execute(() -> {
            try {
                InputStream is = getContentResolver().openInputStream(uri);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
                is.close();
                byte[] fileBytes = bos.toByteArray();

                String result = HCDecryptor.execute(fileBytes);
                currentResult = result;

                uiHandler.post(() -> {
                    tvResult.setText(result);
                    btnCopy.setEnabled(true);
                    if (result.startsWith("❌")) {
                        Toast.makeText(this, "فشل فك التشفير", Toast.LENGTH_LONG).show();
                    } else {
                        Toast.makeText(this, "✅ تم فك التشفير بنجاح", Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Exception e) {
                uiHandler.post(() -> {
                    tvResult.setText("❌ خطأ: " + e.getMessage());
                    btnCopy.setEnabled(false);
                });
            }
        });
    }

    private void copyResult() {
        if (currentResult.isEmpty()) return;
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("HC Result", currentResult));
        Toast.makeText(this, "📋 تم النسخ", Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}