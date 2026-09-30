-- ====================================================================
-- SecureLens: AI-Powered Application Security Platform Database Schema
-- Supabase PostgreSQL with Full Row Level Security (RLS)
-- ====================================================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Profiles / Users Table (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT,
    organization TEXT DEFAULT 'Independent Developer',
    role TEXT DEFAULT 'developer' CHECK (role IN ('owner', 'security_analyst', 'developer', 'viewer')),
    user_type TEXT DEFAULT 'developer' CHECK (user_type IN ('developer', 'student', 'enterprise')),
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 2. Applications Table
CREATE TABLE IF NOT EXISTS public.applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    repository_url TEXT,
    environment TEXT DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development')),
    technology_stack JSONB DEFAULT '{"languages": [], "frameworks": [], "databases": []}'::jsonb,
    current_score INTEGER DEFAULT 100 CHECK (current_score >= 0 AND current_score <= 100),
    previous_score INTEGER,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    last_scanned_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    application_id UUID NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('source_code', 'git_repo', 'zip_upload', 'android_apk', 'web_app', 'api', 'config_files', 'dependencies')),
    target_identifier TEXT, -- e.g., git branch, filename, URL
    status TEXT DEFAULT 'queued' CHECK (status IN ('queued', 'initializing', 'scanning', 'analyzing_ai', 'completed', 'failed')),
    score INTEGER DEFAULT 0,
    score_breakdown JSONB DEFAULT '{"authentication": 100, "authorization": 100, "api_security": 100, "data_protection": 100, "dependencies": 100, "configuration": 100}'::jsonb,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    telemetry_logs JSONB DEFAULT '[]'::jsonb,
    detected_technologies JSONB DEFAULT '[]'::jsonb,
    scanner_version TEXT DEFAULT 'SecureLens Engine v2.4-Core',
    error_message TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- 4. Vulnerabilities Table
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    category TEXT NOT NULL CHECK (category IN ('Authentication', 'Authorization', 'Input Security', 'API Security', 'Secrets', 'Cryptography', 'Configuration', 'Dependencies', 'Infrastructure')),
    description TEXT NOT NULL,
    location TEXT NOT NULL, -- e.g., file path or API endpoint
    line_number INTEGER,
    potential_impact TEXT NOT NULL,
    why_it_matters TEXT NOT NULL,
    recommended_fix TEXT NOT NULL,
    before_code TEXT,
    after_code TEXT,
    code_language TEXT DEFAULT 'javascript',
    cwe_id TEXT,     -- e.g., CWE-89, CWE-798, CWE-862
    owasp_category TEXT, -- e.g., A01:2021-Broken Access Control, A03:2021-Injection
    cvss_score NUMERIC(3,1) DEFAULT 5.0,
    status TEXT DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'false_positive', 'accepted_risk', 'fixed')),
    triage_reason TEXT,
    triaged_by UUID REFERENCES public.profiles(id),
    triaged_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 5. Dependencies Table (SCA)
CREATE TABLE IF NOT EXISTS public.dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    recommended_version TEXT,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'safe')),
    cve_id TEXT,
    advisory_summary TEXT,
    license TEXT DEFAULT 'MIT',
    upgrade_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 6. Team Invitations Table
CREATE TABLE IF NOT EXISTS public.team_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization TEXT NOT NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT DEFAULT 'developer' CHECK (role IN ('owner', 'security_analyst', 'developer', 'viewer')),
    invited_by UUID REFERENCES public.profiles(id),
    status TEXT DEFAULT 'active' CHECK (status IN ('pending', 'active', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 7. Audit & Security Activity Logs
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.profiles(id),
    application_id UUID REFERENCES public.applications(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- ====================================================================
-- Row Level Security (RLS) Policies
-- ====================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can view and edit their own profile
CREATE POLICY "Users can manage own profile" ON public.profiles
    FOR ALL USING (auth.uid() = id);

-- Applications: Users can only see and manage applications they own
CREATE POLICY "Users can manage own applications" ON public.applications
    FOR ALL USING (auth.uid() = user_id);

-- Scans: Users can only see and manage scans they own
CREATE POLICY "Users can manage own scans" ON public.scans
    FOR ALL USING (auth.uid() = user_id);

-- Vulnerabilities: Users can manage vulnerabilities for their scans
CREATE POLICY "Users can manage own vulnerabilities" ON public.vulnerabilities
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM public.applications 
            WHERE applications.id = vulnerabilities.application_id 
            AND applications.user_id = auth.uid()
        )
    );

-- Dependencies: Users can manage dependencies for their scans
CREATE POLICY "Users can manage own dependencies" ON public.dependencies
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM public.applications 
            WHERE applications.id = dependencies.application_id 
            AND applications.user_id = auth.uid()
        )
    );

-- Indexes for lightning fast lookups
CREATE INDEX IF NOT EXISTS idx_applications_user_id ON public.applications(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_app_id ON public.scans(application_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON public.vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON public.vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_category ON public.vulnerabilities(category);
CREATE INDEX IF NOT EXISTS idx_dependencies_scan_id ON public.dependencies(scan_id);
