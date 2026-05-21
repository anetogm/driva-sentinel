"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  Shield,
  Globe,
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  Activity,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { getScoreColor, getScoreBg, formatDate } from "@/lib/utils";

export default function DashboardPage() {
  const router = useRouter();
  const { data: stats } = useQuery({
    queryKey: ["scan-stats"],
    queryFn: api.scans.stats,
  });

  useEffect(() => {
    router.push("/");
  }, [router]);

  return null;
}
