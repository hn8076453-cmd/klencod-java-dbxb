package shshsb.sbsbsbdb;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
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
        
        // بناء الواجهة برمجياً (لتجنب أخطاء R.layout)
        LinearLayout rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("🔓 HC Decryptor\nاختر ملف .hc لفك تشفيره");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 30);
        rootLayout.addView(title);

        Button btnPick = new Button(this);
        btnPick.setText("📂 اختر ملف .hc");
        rootLayout.addView(btnPick);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1.0f);
        params.setMargins(0, 30, 0, 30);
        scrollView.setLayoutParams(params);

        tvResult = new TextView(this);
        tvResult.setText("لم يتم اختيار ملف بعد...");
        tvResult.setTextIsSelectable(true);
        tvResult.setPadding(16, 16, 16, 16);
        scrollView.addView(tvResult);
        rootLayout.addView(scrollView);

        btnCopy = new Button(this);
        btnCopy.setText("📋 نسخ النتيجة");
        btnCopy.setEnabled(false);
        rootLayout.addView(btnCopy);

        setContentView(rootLayout);

        btnPick.setOnClickListener(v -> pickFile());
        btnCopy.setOnClickListener(v -> copyResult());

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