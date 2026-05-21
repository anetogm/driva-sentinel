"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  ArrowLeft,
  Clock,
  Globe,
  ChevronDown,
  CheckCircle2,
  XCircle,
  Loader2,
  Download,
  RotateCcw,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { api } from "@/lib/api";
import {
  getScoreColor,
  getScoreBg,
  getSeverityColor,
  formatDate,
} from "@/lib/utils";
import type { ScanDetail, Finding, ScanProgress } from "@/types";

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [pollInterval, setPollInterval] = useState(2000);

  const { data: scan, refetch: refetchScan } = useQuery<ScanDetail>({
    queryKey: ["scan", id],
    queryFn: () => api.scans.get(id),
    refetchInterval: pollInterval,
  });

  const { data: progress } = useQuery<ScanProgress>({
    queryKey: ["scan-progress", id],
    queryFn: () => api.scans.progress(id),
    refetchInterval: pollInterval,
    enabled: scan?.status === "pending" || scan?.status === "running",
  });

  useEffect(() => {
    if (scan?.status === "completed" || scan?.status === "failed") {
      setPollInterval(0);
    }
  }, [scan?.status]);

  if (!scan) {
    return (
      <div className="min-h-screen bg-[#0a0f1a] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
      </div>
    );
  }

  const isRunning = scan.status === "pending" || scan.status === "running";

  return (
    <div className="min-h-screen bg-[#0a0f1a]">
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="flex items-center gap-4 mb-8">
          <Link
            href="/"
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Link>
        </div>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Globe className="w-5 h-5 text-gray-400" />
            <h1 className="text-xl font-mono text-gray-300">{scan.target_url}</h1>
          </div>
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatDate(scan.created_at)}
            </span>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                scan.status === "completed"
                  ? "bg-emerald-500/10 text-emerald-400"
                  : scan.status === "failed"
                  ? "bg-red-500/10 text-red-400"
                  : scan.status === "running"
                  ? "bg-blue-500/10 text-blue-400"
                  : "bg-gray-500/10 text-gray-400"
              }`}
            >
              {scan.status}
            </span>
          </div>
        </div>

        {isRunning && progress && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass rounded-xl p-6 mb-8"
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Loader2 className="w-5 h-5 animate-spin text-blue-400" />
                <span className="font-medium">Scan in progress...</span>
              </div>
              <span className="text-sm text-gray-400">
                {Math.round(progress.progress)}%
              </span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-blue-500 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${progress.progress}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
          </motion.div>
        )}

        {scan.status === "completed" && (
          <>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className={`glass rounded-2xl p-8 mb-8 border ${getScoreBg(
                scan.rating
              )}`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-400 mb-1">Security Score</p>
                  <div className="flex items-baseline gap-3">
                    <span className={`text-6xl font-bold ${getScoreColor(scan.rating)}`}>
                      {scan.score}
                    </span>
                    <span className="text-3xl font-bold text-gray-500">/100</span>
                  </div>
                  <div className="flex items-center gap-2 mt-2">
                    <span
                      className={`text-2xl font-bold ${getScoreColor(
                        scan.rating
                      )}`}
                    >
                      {scan.rating}
                    </span>
                    <span className="text-sm text-gray-400">
                      rating
                    </span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-bold text-gray-300">
                    {scan.findings_count}
                  </div>
                  <p className="text-sm text-gray-400">findings</p>
                </div>
              </div>
            </motion.div>

            {scan.metadata?.summary && (
              <div className="grid grid-cols-5 gap-4 mb-8">
                {[
                  { label: "Critical", key: "critical", color: "bg-red-600" },
                  { label: "High", key: "high", color: "bg-red-500" },
                  { label: "Medium", key: "medium", color: "bg-orange-500" },
                  { label: "Low", key: "low", color: "bg-yellow-500" },
                  { label: "Info", key: "info", color: "bg-gray-500" },
                ].map((sev) => (
                  <div key={sev.key} className="glass rounded-xl p-4 text-center">
                    <div className={`text-2xl font-bold ${sev.color.replace("bg-", "text-")}`}>
                      {scan.metadata.summary[sev.key] || 0}
                    </div>
                    <p className="text-xs text-gray-400 mt-1">{sev.label}</p>
                  </div>
                ))}
              </div>
            )}

            {scan.findings && scan.findings.length > 0 && (
              <div className="space-y-3">
                <h2 className="text-lg font-semibold mb-4">Findings</h2>
                <AnimatePresence>
                  {scan.findings.map((finding: Finding, index: number) => (
                    <motion.div
                      key={finding.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.03 }}
                      className="glass rounded-xl overflow-hidden"
                    >
                      <button
                        onClick={() =>
                          setExpandedFinding(
                            expandedFinding === finding.id ? null : finding.id
                          )
                        }
                        className="w-full px-6 py-4 flex items-center gap-4 text-left"
                      >
                        <span
                          className={`px-2 py-1 rounded text-xs font-bold uppercase ${getSeverityColor(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="px-2 py-1 rounded text-xs bg-white/5 text-gray-400">
                          {finding.scanner}
                        </span>
                        <span className="flex-1 font-medium text-sm">
                          {finding.title}
                        </span>
                        <ChevronDown
                          className={`w-4 h-4 text-gray-400 transition-transform ${
                            expandedFinding === finding.id ? "rotate-180" : ""
                          }`}
                        />
                      </button>
                      <AnimatePresence>
                        {expandedFinding === finding.id && (
                          <motion.div
                            initial={{ height: 0 }}
                            animate={{ height: "auto" }}
                            exit={{ height: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="px-6 pb-4 pt-2 border-t border-white/5">
                              <p className="text-sm text-gray-400 mb-3">
                                {finding.description}
                              </p>
                              {finding.recommendation && (
                                <div className="bg-blue-500/5 border border-blue-500/10 rounded-lg p-3">
                                  <p className="text-sm text-blue-400 font-medium mb-1">
                                    Recommendation
                                  </p>
                                  <p className="text-sm text-gray-400">
                                    {finding.recommendation}
                                  </p>
                                </div>
                              )}
                              {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                                <div className="mt-3">
                                  <p className="text-xs text-gray-500 mb-1">Evidence</p>
                                  <pre className="text-xs text-gray-400 bg-black/30 rounded-lg p-3 overflow-x-auto font-mono">
                                    {JSON.stringify(finding.evidence, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            )}
          </>
        )}

        {scan.status === "failed" && (
          <div className="glass rounded-xl p-8 text-center">
            <XCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2">Scan Failed</h2>
            <p className="text-gray-400 mb-4">
              The scan could not be completed. Please try again.
            </p>
            <button
              onClick={() => api.scans.rescan(id)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-sm font-medium transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Retry Scan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
