import Link from 'next/link';

/**
 * Landing page — SafeRepo home.
 * Public page with sign-in link.
 */
export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8">
      <div className="max-w-2xl text-center">
        <h1 className="text-4xl font-bold mb-4">SafeRepo</h1>
        <p className="text-lg text-gray-600 dark:text-gray-400 mb-8">
          Analyze a GitHub repository&apos;s security posture before you run it,
          depend on it, or trust it.
        </p>
        <Link
          href="/login"
          className="inline-block rounded-lg bg-gray-900 dark:bg-white dark:text-gray-900 px-6 py-3 text-white font-medium hover:opacity-90 transition-opacity"
        >
          Sign in with GitHub
        </Link>
      </div>
    </main>
  );
}
