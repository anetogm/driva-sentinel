"use client";

import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  Clock,
  Globe,
  ArrowRight,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { getScoreColor, formatDate } from "@/lib/utils";
import type { ScanListResponse } from "@/types";

export default function HistoryPage() {
  const [page, setPage] = useState(0);
  const limit = 20;

  const { data } = useQuery<ScanListResponse>({
    queryKey: ["scans", page],
    queryFn: () => api.scans.list(page * limit, limit),
  });

  const scans = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);

  return (
    <div className="min-h-screen bg-[#0a0f1a]">
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold">Scan History</h1>
            <p className="text-gray-400 text-sm mt-1">
              {total} total scans
            </p>
          </div>
          <Link
            href="/"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-sm font-medium transition-colors"
          >
            <Shield className="w-4 h-4" />
            New Scan
          </Link>
        </div>

        <div className="glass rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/5 text-left text-xs uppercase text-gray-500">
                <th className="px-6 py-3 font-medium">Target</th>
                <th className="px-6 py-3 font-medium">Status</th>
                <th className="px-6 py-3 font-medium">Score</th>
                <th className="px-6 py-3 font-medium">Rating</th>
                <th className="px-6 py-3 font-medium">Findings</th>
                <th className="px-6 py-3 font-medium">Date</th>
                <th className="px-6 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan, i) => (
                <motion.tr
                  key={scan.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  className="border-b border-white/5 hover:bg-white/5 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-gray-500" />
                      <span className="font-mono text-sm text-gray-300 truncate max-w-[200px]">
                        {scan.target_url}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
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
                  </td>
                  <td className="px-6 py-4">
                    <span className="font-mono font-bold">
                      {scan.score !== null ? scan.score : "-"}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {scan.rating ? (
                      <span className={`font-bold ${getScoreColor(scan.rating)}`}>
                        {scan.rating}
                      </span>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-400">
                    {scan.findings_count}
                  </td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1 text-sm text-gray-400">
                      <Clock className="w-3 h-3" />
                      {formatDate(scan.created_at)}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="p-2 hover:bg-white/5 rounded-lg transition-colors"
                      >
                        <ArrowRight className="w-4 h-4 text-gray-400" />
                      </Link>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 mt-6">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-2 hover:bg-white/5 rounded-lg disabled:opacity-30 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm text-gray-400">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-2 hover:bg-white/5 rounded-lg disabled:opacity-30 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
