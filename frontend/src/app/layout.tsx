import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";
import { AppShell } from "@/components/layout/app-shell";

export const metadata: Metadata = {
  title: "SENTINEL IR — Enterprise Security Operations & Incident Response",
  description:
    "Enterprise Security Incident Response, Threat Intelligence Enrichment, Investigation & SOAR Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="bg-soc-bg text-soc-text font-sans selection:bg-sky-500/30 selection:text-sky-100">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
