# Security Mitigation Plan - RustZAP Scan Report
**Target:** http://localhost:3001  
**Scan Date:** 2026-04-17  
**Risk Score:** 72/100  
**Total Findings:** 24 (0 Critical, 0 High, 10 Medium, 8 Low, 6 Info)

---

## Executive Summary

Your application has **moderate security vulnerabilities** primarily related to missing HTTP security headers and information disclosure risks. The good news: **no critical or high-severity vulnerabilities were found**. All issues are fixable by implementing proper security headers and production configurations.

**Priority:** 
- 🔴 **Critical Path:** Implement missing HTTP security headers (affects all 3 URLs)
- 🟡 **Medium Priority:** Fix information disclosure issues
- 🟢 **Low Priority:** Add legacy browser support headers (info-level issues)

---

## Detailed Mitigation Strategy

### **1. MEDIUM SEVERITY - Missing HTTP Security Headers (10 findings)**

These headers are missing across all discovered URLs (http://localhost:3001, /@vite/client, /index.tsx).

#### A. **HSTS Header** (3 findings) - CWE-16
**Issue:** Server not enforcing HTTPS via HSTS. Browsers may allow HTTP connections.

**Solution:**
```nginx
# Nginx configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# OR Apache
Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# OR Express.js
app.use((req, res, next) => {
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});
```

**Implementation Timeline:** Week 1 - Critical (enables HTTPS-only browsing)

---

#### B. **X-Frame-Options Header** (3 findings) - CWE-1021
**Issue:** Page can be embedded in iframes, enabling clickjacking attacks.

**Solution:**
```nginx
# Nginx
add_header X-Frame-Options "DENY" always;
# Or use "SAMEORIGIN" if you need embedding within your domain

# Express.js (using helmet.js)
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
```

**Implementation Timeline:** Week 1 - Critical (prevents clickjacking)

---

#### C. **Content-Security-Policy Header** (3 findings) - CWE-1021
**Issue:** No CSP header found. XSS attacks may be more impactful.

**Solution:**
```nginx
# Nginx - Start strict, then relax as needed
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'" always;

# Express.js (using helmet.js)
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));
```

**Implementation Timeline:** Week 1 - Critical (prevents XSS impacts)

---

### **2. LOW SEVERITY - Missing Security Headers (8 findings)**

#### A. **X-Content-Type-Options Header** (3 findings) - CWE-693
**Issue:** Without nosniff, browsers may MIME-sniff responses, enabling XSS attacks.

**Solution:**
```nginx
add_header X-Content-Type-Options "nosniff" always;

# Express.js (helmet.js)
app.use(helmet.noSniff());
```

**Implementation Timeline:** Week 1 - Essential (prevents MIME-sniffing attacks)

---

#### B. **Referrer-Policy Header** (3 findings) - CWE-116
**Issue:** Without a Referrer-Policy, sensitive URLs may be leaked via Referer header.

**Solution:**
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Express.js
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
```

**Implementation Timeline:** Week 1 - Important (prevents URL leakage)

---

#### C. **Content-Type Charset** (1 finding) - CWE-116
**Issue:** Content-Type header for HTML does not specify charset (character encoding attack vector).

**Solution:**
```nginx
# Nginx
add_header Content-Type "text/html; charset=UTF-8" always;

# Express.js
app.use((req, res, next) => {
  res.set('Content-Type', 'text/html; charset=UTF-8');
  next();
});
```

**Implementation Timeline:** Week 1 - Essential

---

#### D. **Cache-Control Header** (1 finding) - CWE-525
**Issue:** Response does not set cache-control: no-store, allowing sensitive content to be cached.

**Solution:**
```nginx
# Nginx - for sensitive pages
add_header Cache-Control "no-store, private, no-cache" always;

# Express.js
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, private, no-cache');
  next();
});
```

**Implementation Timeline:** Week 1 - Important (prevents cache attacks)

---

### **3. INFO SEVERITY - Legacy Browser Support (6 findings)**

#### A. **X-XSS-Protection Header** (3 findings) - CWE-693
**Issue:** Legacy XSS filter header not present (affects older browsers like IE, older Edge).

**Solution:**
```nginx
add_header X-XSS-Protection "1; mode=block" always;

# Express.js (helmet.js)
app.use(helmet.xssFilter());
```

**Implementation Timeline:** Week 2 - Optional (legacy browser support)

---

#### B. **Permissions-Policy Header** (3 findings) - CWE-693
**Issue:** No Permissions-Policy restricting browser feature access.

**Solution:**
```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Express.js
app.use(helmet.permittedCrossDomainPolicies());
```

**Implementation Timeline:** Week 2 - Recommended (restricts feature access)

---

### **4. MEDIUM SEVERITY - Information Disclosure (1 finding)**

#### **Stack Trace Detected** - CWE-209
**URL:** http://localhost:3001/@vite/client  
**Issue:** Stack trace/error message detected in response body leaking internal paths.

**Evidence:** "at need to be cleaned up..." suggests JavaScript stack trace in development code.

**Solution:**
```javascript
// 1. In development mode (Vite), source maps are served with stack traces
// PRODUCTION FIX: Disable source maps in production build

// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,  // ← Disable in production
    minify: 'terser',
    terserOptions: {
      compress: { drop_console: true },
      mangle: true
    }
  },
  // Development mode configuration
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  }
})

// 2. Implement error boundary middleware
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    // Return generic error in production
    res.status(500).json({ error: 'Internal Server Error' });
  } else {
    // Return detailed error in development
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// 3. Disable Vite dev server in production
// Ensure you're running built, minified assets only
```

**Implementation Timeline:** Week 1 - Critical (prevents information leakage)

---

## Implementation Roadmap

### **Phase 1: Immediate (Week 1) - Critical**
Priority order for maximum security impact:

1. **Day 1:**
   - [ ] Add HSTS header (all URLs protected)
   - [ ] Add X-Frame-Options (prevent clickjacking)
   - [ ] Add Content-Security-Policy (prevent XSS)

2. **Day 2:**
   - [ ] Add X-Content-Type-Options (prevent MIME-sniffing)
   - [ ] Add Referrer-Policy (prevent URL leakage)
   - [ ] Fix Content-Type charset

3. **Day 3:**
   - [ ] Disable source maps in production build
   - [ ] Implement error handling middleware
   - [ ] Add Cache-Control headers

4. **Day 4:**
   - [ ] Run full security test (re-scan with RustZAP)
   - [ ] Verify all Medium/Low severity issues resolved

### **Phase 2: Secondary (Week 2) - Legacy Support**
- [ ] Add X-XSS-Protection (older browser support)
- [ ] Add Permissions-Policy (feature restriction)

---

## Recommended Framework-Specific Implementations

### **For Express.js + Vite Stack:**

```javascript
// server.js
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';

const app = express();

// Security middleware (must be before routes)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
  noSniff: true,
}));

// Compression
app.use(compression());

// Cache control
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, private, no-cache');
  res.set('Content-Type', 'text/html; charset=UTF-8');
  next();
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal Server Error' 
      : err.message 
  });
});
```

### **For Nginx Reverse Proxy:**

```nginx
server {
    listen 443 ssl http2;
    server_name localhost;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Cache and content type
    add_header Cache-Control "no-store, private, no-cache" always;
    charset UTF-8;

    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Testing & Validation

### **Step 1: Unit Test Headers**
```bash
# Test header presence
curl -I http://localhost:3001 | grep -E "Strict-Transport-Security|X-Frame-Options|Content-Security-Policy"

# Expected output:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Frame-Options: DENY
# Content-Security-Policy: ...
```

### **Step 2: Re-scan with RustZAP**
```bash
./target/release/rustzap scan --target http://localhost:3001 --output remediated-report.json
```

### **Step 3: Security Validation Tools**
- **Mozilla Observatory:** https://observatory.mozilla.org/
- **OWASP ZAP:** Full active scanning
- **Burp Suite:** Manual penetration testing
- **Lighthouse:** Google's security audit

### **Step 4: Browser Security Headers Check**
```bash
# Online tool
https://securityheaders.com/?q=localhost:3001
```

---

## Risk Assessment After Mitigation

| Finding | Before | After | Status |
|---------|--------|-------|--------|
| HSTS Header | ❌ Missing | ✅ Implemented | RESOLVED |
| X-Frame-Options | ❌ Missing | ✅ DENY | RESOLVED |
| Content-Security-Policy | ❌ Missing | ✅ Configured | RESOLVED |
| X-Content-Type-Options | ❌ Missing | ✅ nosniff | RESOLVED |
| Referrer-Policy | ❌ Missing | ✅ Configured | RESOLVED |
| Content-Type Charset | ❌ Missing | ✅ UTF-8 | RESOLVED |
| Cache-Control | ❌ Missing | ✅ no-store | RESOLVED |
| Stack Trace Disclosure | ❌ Exposed | ✅ Disabled | RESOLVED |
| X-XSS-Protection | ❌ Missing | ✅ Added | RESOLVED |
| Permissions-Policy | ❌ Missing | ✅ Added | RESOLVED |

**Expected Result After Implementation:**
- Current Risk Score: **72/100**
- Post-Mitigation Risk Score: **0-5/100** (Excellent)
- Security Grade: **A** (on most security scanners)

---

## Maintenance & Ongoing Security

### **Monthly Tasks:**
- [ ] Re-run RustZAP scan
- [ ] Check for new security headers (Referrer-Policy, Permissions-Policy updates)
- [ ] Review dependency security advisories

### **Quarterly Tasks:**
- [ ] Full penetration test
- [ ] Security header audit
- [ ] Update security policies documentation

### **Annually:**
- [ ] Professional security assessment
- [ ] Update security training
- [ ] Review and update this mitigation plan

---

## References & Additional Resources

- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [CWE Database](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Helmet.js Documentation](https://helmetjs.github.io/)

---

**Report Generated:** 2026-04-18  
**Next Review Date:** 2026-05-18  
**Owner:** Security Team  
**Status:** In Progress
