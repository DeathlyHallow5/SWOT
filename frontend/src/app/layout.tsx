import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SWOT — Smart Website OSINT Tool",
  description: "Authorized website reconnaissance toolkit.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
