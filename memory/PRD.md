# BureauSmart - PRD (Product Requirements Document)

## Original Problem Statement
Bureaucracy Intelligence Engine (BureauSmart). An app that analyzes highly complex official letters, invoices, and contracts and translates them into simple, actionable data.
- Input: OCR/Image/PDF
- Output JSON: summary, action_needed, deadline, amount_due, sender, priority, user_options (Pay/Appeal/Ask) with drafts, easy explanation
- Requirements: Gemini 3 Flash, Document History with search, JWT Auth & Stripe (2.99 EUR/mo)
- Multilingual document processing and multilingual UI
- Forgot Password flow via SMTP email

## Tech Stack
- Frontend: React + Shadcn UI + Phosphor Icons
- Backend: FastAPI + Motor (async MongoDB)
- Database: MongoDB
- AI: Gemini 3 Flash (via Emergent Integrations)
- Payments: Stripe (direct library, subscription mode) - LIVE KEY
- Storage: Emergent Object Storage
- Email: Gmail SMTP (smtplib)
- Auth: JWT (bcrypt + PyJWT)

## Core Features (All Implemented & Tested)
1. JWT Authentication (register, login, logout, refresh, brute-force protection)
2. Forgot Password flow (SMTP 6-digit code, 15-min expiry, max 5 attempts)
3. Document Upload (JPG, PNG, WebP, PDF via Object Storage)
4. AI Document Analysis (Gemini 3 Flash - multilingual)
5. Auto-Translation of analysis to match UI language
6. AI Text Generation for response drafts (subscribers only)
7. AI Text Improvement (subscribers only)
8. Document History with search
9. Stripe Subscription (2.99 EUR/mo, recurring monthly via stripe_price_id)
10. Multilingual UI (14 languages: DE, EN, FR, ES, IT, NL, PL, TR, PT, RU, AR, ZH, JA, KO)
11. Language Switcher component
12. Paywall enforcement (backend + frontend)

## Status: PRODUCTION READY

## Future/Backlog Tasks (Not Started)
- P2: Document Export/Download functionality
- P3: Deadline overview/calendar tab
- Refactoring: translations.js split into separate JSON files per language
