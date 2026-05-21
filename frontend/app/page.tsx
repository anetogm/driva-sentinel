"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Shield, ScanLine, Zap, Lock, Globe, BarChart3, ArrowRight, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";

export default function HomePage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError("");

    try {
      const scan = await api.scans.create(url.trim());
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      setError(err.message || "Failed to start scan");
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0f1a] relative overflow-hidden">
      <div className="absolute inset-0 scan-grid opacity-50" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-blue-500/10 rounded-full blur-[120px]" />

      <nav className="relative z-10 border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            <span className="font-bold text-lg tracking-tight">KindMelody</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-gray-400">
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#how-it-works" className="hover:text-white transition-colors">How it works</a>
            <a href="/dashboard" className="hover:text-white transition-colors">Dashboard</a>
          </div>
        </div>
      </nav>

      <main className="relative z-10">
        <section className="pt-24 pb-16 px-6">
          <div className="max-w-4xl mx-auto text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm mb-8">
                <ShieldCheck className="w-4 h-4" />
                Enterprise-grade security scanning
              </div>
              <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6">
                Secure your
                <span className="text-gradient"> digital presence</span>
              </h1>
              <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-12">
                Deep security analysis of any website. Detect vulnerabilities, misconfigurations,
                and get actionable recommendations to harden your security posture.
              </p>
            </motion.div>

            <motion.form
              onSubmit={handleSubmit}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="max-w-2xl mx-auto"
            >
              <div className="relative">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter a URL to scan (e.g., example.com)"
                  className="w-full h-14 pl-6 pr-36 rounded-xl bg-white/5 border border-white/10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !url.trim()}
                  className="absolute right-2 top-2 h-10 px-6 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <ScanLine className="w-4 h-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      Scan Now
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
              {error && (
                <p className="mt-3 text-red-400 text-sm">{error}</p>
              )}
            </motion.form>
          </div>
        </section>

        <section id="features" className="py-20 px-6 border-t border-white/5">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-3xl font-bold mb-4">Comprehensive Security Checks</h2>
              <p className="text-gray-400">7 specialized scanners covering every angle of web security</p>
            </div>
            <div className="grid md:grid-cols-3 gap-6">
              {[
                {
                  icon: Lock,
                  title: "Headers Analysis",
                  desc: "CSP, HSTS, X-Frame-Options, cookies, CORS and more",
                },
                {
                  icon: Shield,
                  title: "TLS/SSL Verification",
                  desc: "Certificate validity, cipher strength, protocol versions",
                },
                {
                  icon: Globe,
                  title: "DNS Security",
                  desc: "SPF, DMARC, DKIM, DNSSEC, CAA records analysis",
                },
                {
                  icon: Zap,
                  title: "Web Exposure",
                  desc: "Exposed files, admin panels, backup files, .git leaks",
                },
                {
                  icon: BarChart3,
                  title: "Technology Detection",
                  desc: "Frameworks, CMS, WAF, CDN, server identification",
                },
                {
                  icon: ScanLine,
                  title: "Fingerprinting",
                  desc: "Server headers, cookie analysis, technology stack",
                },
              ].map((feature, i) => (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.1 }}
                  viewport={{ once: true }}
                  className="glass rounded-xl p-6 hover:bg-white/10 transition-colors"
                >
                  <feature.icon className="w-8 h-8 text-blue-400 mb-4" />
                  <h3 className="font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-gray-400">{feature.desc}</p>
                </motion.div>
              ))}
            </div>
          </div>
        </section>

        <section id="how-it-works" className="py-20 px-6 border-t border-white/5">
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-16">
              <h2 className="text-3xl font-bold mb-4">How It Works</h2>
              <p className="text-gray-400">From URL to actionable security report in seconds</p>
            </div>
            <div className="grid md:grid-cols-4 gap-8">
              {[
                { step: "01", title: "Enter URL", desc: "Submit any website URL for analysis" },
                { step: "02", title: "Deep Scan", desc: "7 specialized scanners run in parallel" },
                { step: "03", title: "Score & Rate", desc: "Weighted scoring with A+ to F rating" },
                { step: "04", title: "Fix Issues", desc: "Get specific remediation guidance" },
              ].map((item) => (
                <div key={item.step} className="text-center">
                  <div className="text-4xl font-bold text-blue-500/30 mb-4">{item.step}</div>
                  <h3 className="font-semibold mb-2">{item.title}</h3>
                  <p className="text-sm text-gray-400">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <footer className="py-8 px-6 border-t border-white/5">
          <div className="max-w-6xl mx-auto flex items-center justify-between text-sm text-gray-500">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              <span>KindMelody Security Scanner</span>
            </div>
            <span>Enterprise-grade security analysis</span>
          </div>
        </footer>
      </main>
    </div>
  );
}
