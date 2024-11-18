
package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.stripe.Stripe;
import com.stripe.model.PaymentIntent;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MainController {

    public MainController() {
        // Set your Stripe secret key
        Stripe.apiKey = "sk_test_51Ha6EUEsCFPlCMG1zxzWoFCMCkMdTEEnxmtsY54cDJ1ZCMebV8NwxX9V9IFrDojB0nhtXTdhk1EVVD1KDiUUPi9g00gVqMcbFl";
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        // Handle file upload logic
        return ResponseEntity.ok("File uploaded successfully: " + file.getOriginalFilename());
    }

    @GetMapping("/funds")
    public ResponseEntity<String> getFunds() {
        // Placeholder for fetching funds
        return ResponseEntity.ok("Fetching funds...");
    }

    @PostMapping("/payment")
    public ResponseEntity<String> processPayment(@RequestBody Map<String, Object> paymentData) {
        try {
            // Create a PaymentIntent with Stripe
            Map<String, Object> params = new HashMap<>();
            params.put("amount", paymentData.get("amount"));
            params.put("currency", "usd");
            params.put("payment_method", paymentData.get("paymentMethodId"));
            params.put("confirmation_method", "manual");
            params.put("confirm", true);

            PaymentIntent paymentIntent = PaymentIntent.create(params);
            return ResponseEntity.ok(paymentIntent.toJson());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Payment failed: " + e.getMessage());
        }
    }
}
