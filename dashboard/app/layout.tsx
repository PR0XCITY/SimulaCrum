import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { ModeProvider } from "@/components/ModeProvider";
import { AppShell } from "@/components/AppShell";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SimulaCrum",
  description: "Risk certificates for Terraform plans: policy, blast radius, shadow run and cost.",
  // The UI is already dark: ask the Dark Reader extension not to restyle it.
  // (Next.js drops empty values; Dark Reader only checks the tag exists.)
  other: { "darkreader-lock": "true" },
};

export const viewport: Viewport = {
  themeColor: "#09090b",
  colorScheme: "dark",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // suppressHydrationWarning covers only this element's attributes, which browser
    // extensions (e.g. Dark Reader's data-darkreader-*) add before React hydrates.
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="min-h-full">
        <ModeProvider>
          <AppShell>{children}</AppShell>
        </ModeProvider>
      </body>
    </html>
  );
}
