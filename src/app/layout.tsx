import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { SecurityProvider } from '@/context/SecurityContext';

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SecureLens — AI-Powered Application Security Platform',
  description: 'See the Risk. Fix the Risk. Automated SAST, SCA, secret detection, and API security analysis with developer-friendly AI remediation.',
  keywords: ['cybersecurity', 'application security', 'SAST', 'SCA', 'vulnerability scanner', 'code audit', 'devsecops'],
  authors: [{ name: 'SecureLens Security Labs' }],
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans min-h-screen bg-[#070a11] text-slate-100 antialiased`}>
        <SecurityProvider>
          {children}
        </SecurityProvider>
      </body>
    </html>
  );
}
