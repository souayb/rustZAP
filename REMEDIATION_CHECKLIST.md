# Security Remediation Checklist
**Application:** localhost:3001  
**Date Started:** 2026-04-18  
**Target Completion:** 2026-04-25  

---

## 🔴 PHASE 1: CRITICAL (Week 1 - Days 1-4)

### Day 1: Core Security Headers
- [ ] **HSTS Header (Strict-Transport-Security)**
  - [ ] Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - [ ] Applies to: All URLs
  - [ ] Priority: CRITICAL
  - [ ] Estimated time: 15 mins
  - [ ] Testing command: `curl -I http://localhost:3001 | grep HSTS`

- [ ] **X-Frame-Options (Clickjacking Protection)**
  - [ ] Add header: `X-Frame-Options: DENY`
  - [ ] Applies to: All URLs
  - [ ] Priority: CRITICAL
  - [ ] Estimated time: 15 mins

- [ ] **Content-Security-Policy (XSS Prevention)**
  - [ ] Add header: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`
  - [ ] Applies to: All URLs
  - [ ] Priority: CRITICAL
  - [ ] Estimated time: 45 mins
  - [ ] Test: Check browser console for CSP violations

**Day 1 Subtotal:** ~75 minutes

---

### Day 2: Additional Security Headers
- [ ] **X-Content-Type-Options (MIME-Sniffing Protection)**
  - [ ] Add header: `X-Content-Type-Options: nosniff`
  - [ ] Applies to: All URLs
  - [ ] Priority: HIGH
  - [ ] Estimated time: 15 mins

- [ ] **Referrer-Policy (URL Leakage Prevention)**
  - [ ] Add header: `Referrer-Policy: strict-origin-when-cross-origin`
  - [ ] Applies to: All URLs
  - [ ] Priority: HIGH
  - [ ] Estimated time: 15 mins

- [ ] **Content-Type Charset Fix**
  - [ ] Update header: `Content-Type: text/html; charset=UTF-8`
  - [ ] Applies to: HTML responses
  - [ ] Priority: HIGH
  - [ ] Estimated time: 15 mins
  - [ ] Test: View page source → check Content-Type

**Day 2 Subtotal:** ~45 minutes

---

### Day 3: Production Configuration & Information Disclosure
- [ ] **Cache-Control Header**
  - [ ] Add header: `Cache-Control: no-store, private, no-cache`
  - [ ] Applies to: Sensitive pages
  - [ ] Priority: HIGH
  - [ ] Estimated time: 15 mins

- [ ] **Disable Source Maps in Production**
  - [ ] Edit `vite.config.ts`: Set `sourcemap: false` in build config
  - [ ] Applies to: Production build
  - [ ] Priority: CRITICAL (Stack trace prevention)
  - [ ] Estimated time: 20 mins
  - [ ] Test: Build production, check /@vite/client response

- [ ] **Error Handling Middleware**
  - [ ] Implement generic error responses in production
  - [ ] Remove stack traces from HTTP responses
  - [ ] Applies to: All error pages
  - [ ] Priority: CRITICAL
  - [ ] Estimated time: 30 mins

- [ ] **Build & Test Production Bundle**
  - [ ] Run: `npm run build`
  - [ ] Verify no .map files in dist
  - [ ] Test error pages show generic messages
  - [ ] Estimated time: 10 mins

**Day 3 Subtotal:** ~75 minutes

---

### Day 4: Verification & Re-scan
- [ ] **Manual Header Validation**
  - [ ] [ ] Test with curl all 3 URLs
  - [ ] [ ] Verify all headers present
  - [ ] [ ] Check header values are correct
  - [ ] Estimated time: 20 mins

- [ ] **Security Header Audit Sites**
  - [ ] [ ] Test on securityheaders.com
  - [ ] [ ] Test on mozilla.org observatory
  - [ ] Estimated time: 15 mins

- [ ] **RustZAP Re-scan**
  - [ ] Run full scan again: `./target/release/rustzap scan --target http://localhost:3001 --output remediated-report.json`
  - [ ] Compare findings count
  - [ ] Expected result: 0 Medium, 0 Low (only Info remaining)
  - [ ] Estimated time: 30 mins

- [ ] **Document Results**
  - [ ] [ ] Compare before/after reports
  - [ ] [ ] Create remediation summary
  - [ ] [ ] Note any remaining Info-level issues
  - [ ] Estimated time: 15 mins

**Day 4 Subtotal:** ~80 minutes

**PHASE 1 TOTAL: ~275 minutes (~4.5 hours)**

---

## 🟡 PHASE 2: LEGACY SUPPORT (Week 2 - Optional)

### Day 5: Legacy Browser Headers
- [ ] **X-XSS-Protection (IE/Older Edge)**
  - [ ] Add header: `X-XSS-Protection: 1; mode=block`
  - [ ] Browser support: IE9-11, Edge Legacy
  - [ ] Priority: LOW (mostly obsolete)
  - [ ] Estimated time: 15 mins

- [ ] **Permissions-Policy (Feature Restriction)**
  - [ ] Add header: `Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=()`
  - [ ] Applies to: All URLs
  - [ ] Priority: MEDIUM (modern browsers)
  - [ ] Estimated time: 20 mins

**PHASE 2 TOTAL: ~35 minutes (~1 hour)**

---

## 📋 Implementation Checklist by Technology

### If using **Express.js + Helmet:**
```bash
npm install helmet
```

- [ ] Import helmet in server.js
- [ ] Add helmet configuration for all headers
- [ ] Test with curl and browser DevTools
- [ ] Estimated time: 30 mins

### If using **Nginx:**
```bash
sudo vi /etc/nginx/sites-available/default
```

- [ ] Add all security headers to server block
- [ ] Test nginx config: `sudo nginx -t`
- [ ] Reload: `sudo systemctl reload nginx`
- [ ] Estimated time: 20 mins

### If using **Apache:**
```bash
sudo a2enmod headers
sudo vi /etc/apache2/sites-available/000-default.conf
```

- [ ] Add all security headers to VirtualHost
- [ ] Enable mod_headers if not already
- [ ] Reload: `sudo systemctl reload apache2`
- [ ] Estimated time: 20 mins

### If using **Vite + Vite Plugin:**
- [ ] Install vite-plugin-csp plugin (optional but recommended)
- [ ] Configure vite.config.ts with CSP settings
- [ ] Disable sourcemap in production build
- [ ] Estimated time: 45 mins

---

## ✅ Testing Procedures

### Test 1: Header Presence (curl)
```bash
# Run this after each implementation
curl -I http://localhost:3001

# Expected headers:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Frame-Options: DENY
# Content-Security-Policy: default-src 'self'...
# X-Content-Type-Options: nosniff
# Referrer-Policy: strict-origin-when-cross-origin
# Cache-Control: no-store, private, no-cache
# X-XSS-Protection: 1; mode=block
# Permissions-Policy: geolocation=(), microphone=()...
```

### Test 2: Browser DevTools
- [ ] Open http://localhost:3001
- [ ] Press F12 → Network tab
- [ ] Refresh page
- [ ] Click main document request
- [ ] Check "Response Headers" section
- [ ] Verify all expected headers present

### Test 3: Online Security Scanner
- [ ] Visit: https://securityheaders.com
- [ ] Enter: http://localhost:3001
- [ ] Expected grade: **A** (or higher)

### Test 4: Mozilla Observatory
- [ ] Visit: https://observatory.mozilla.org
- [ ] Scan: http://localhost:3001
- [ ] Expected score: **90+**

### Test 5: RustZAP Re-scan
```bash
./target/release/rustzap scan \
  --target http://localhost:3001 \
  --output remediated-report.json \
  --plugins all

# Check summary - should show:
# - total_findings: < 10 (down from 24)
# - critical: 0
# - high: 0
# - medium: 0 or minimal
# - low: 0 or minimal
```

---

## 🔍 Finding-by-Finding Status Tracking

| ID | Finding | Severity | Status | Completed By | Notes |
|----|---------|----------|--------|--------------|-------|
| 1 | Missing HSTS Header | Medium | ⏳ TODO | | Implement server config |
| 2 | Missing X-Frame-Options | Medium | ⏳ TODO | | Prevent clickjacking |
| 3 | Missing CSP | Medium | ⏳ TODO | | Prevent XSS |
| 4 | Missing HSTS (/@vite/client) | Medium | ⏳ TODO | | Same as #1 |
| 5 | Missing X-Frame-Options (/@vite/client) | Medium | ⏳ TODO | | Same as #2 |
| 6 | Missing CSP (/@vite/client) | Medium | ⏳ TODO | | Same as #3 |
| 7 | Stack Trace Detected | Medium | ⏳ TODO | | Disable source maps |
| 8 | Missing HSTS (/index.tsx) | Medium | ⏳ TODO | | Same as #1 |
| 9 | Missing X-Frame-Options (/index.tsx) | Medium | ⏳ TODO | | Same as #2 |
| 10 | Missing CSP (/index.tsx) | Medium | ⏳ TODO | | Same as #3 |
| 11 | Missing X-Content-Type-Options | Low | ⏳ TODO | | Add nosniff header |
| 12 | Missing Referrer-Policy | Low | ⏳ TODO | | Strict-origin-when-cross-origin |
| 13 | Missing Content-Type Charset | Low | ⏳ TODO | | Add charset=UTF-8 |
| 14 | Sensitive Page May Be Cached | Low | ⏳ TODO | | Set cache-control |
| 15 | Missing X-Content-Type-Options (/@vite/client) | Low | ⏳ TODO | | Same as #11 |
| 16 | Missing Referrer-Policy (/@vite/client) | Low | ⏳ TODO | | Same as #12 |
| 17 | Missing X-Content-Type-Options (/index.tsx) | Low | ⏳ TODO | | Same as #11 |
| 18 | Missing Referrer-Policy (/index.tsx) | Low | ⏳ TODO | | Same as #12 |
| 19 | Missing X-XSS-Protection | Info | ⏳ TODO | | Legacy support (optional) |
| 20 | Missing Permissions-Policy | Info | ⏳ TODO | | Feature restriction |
| 21 | Missing X-XSS-Protection (/@vite/client) | Info | ⏳ TODO | | Same as #19 |
| 22 | Missing Permissions-Policy (/@vite/client) | Info | ⏳ TODO | | Same as #20 |
| 23 | Missing X-XSS-Protection (/index.tsx) | Info | ⏳ TODO | | Same as #19 |
| 24 | Missing Permissions-Policy (/index.tsx) | Info | ⏳ TODO | | Same as #20 |

---

## 📊 Progress Metrics

**Start Date:** 2026-04-18  
**Target End Date:** 2026-04-25  

### Week 1 Goals
- [ ] Implement all CRITICAL headers (Days 1-3)
- [ ] Fix information disclosure (Day 3)
- [ ] Complete re-scan verification (Day 4)
- [ ] Expected: 0 Medium severity findings

### Week 2 Goals
- [ ] Add legacy browser support headers
- [ ] Final security audit
- [ ] Documentation complete
- [ ] Expected: Only Info-level findings (non-critical)

### Success Criteria
- ✅ All Medium severity findings resolved
- ✅ Security score > 90 on online scanners
- ✅ RustZAP re-scan shows 0-6 total findings (all Info-level)
- ✅ No stack traces in production responses
- ✅ All headers validated via curl and DevTools

---

## 🆘 Troubleshooting Guide

### Issue: Headers not appearing after implementation
**Solution:**
1. Check server config was saved
2. Restart web server (`systemctl restart nginx` or equivalent)
3. Hard refresh browser (Ctrl+Shift+R or Cmd+Shift+R)
4. Check for proxy/cache between browser and server

### Issue: CSP blocks legitimate resources
**Solution:**
1. Check browser console for CSP violations
2. Add allowed domain to CSP directive
3. Consider relaxing CSP if needed for functionality
4. Test incrementally

### Issue: Production build still has source maps
**Solution:**
1. Verify `sourcemap: false` in vite.config.ts
2. Delete dist/ folder completely: `rm -rf dist/`
3. Rebuild: `npm run build`
4. Confirm no .map files: `ls -la dist/assets/ | grep map`

### Issue: Stack traces still visible
**Solution:**
1. Check error handling middleware is applied
2. Verify environment variable properly set: `NODE_ENV=production`
3. Check middleware order (should be before routes)
4. Test with production build, not dev server

---

## 📞 Support & Escalation

If you encounter issues:
1. Check the SECURITY_MITIGATION_PLAN.md for detailed guidance
2. Refer to framework documentation (Helmet.js, Nginx docs, etc.)
3. Test with online tools (securityheaders.com, observatory)
4. Run RustZAP scan to verify progress

**All findings are routine security misconfigurations - no complex vulnerabilities to fix.**

---

**Last Updated:** 2026-04-18  
**Status:** Ready for Implementation  
**Estimated Total Time:** 5-6 hours for complete remediation
