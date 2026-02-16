'use client';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen flex items-center justify-center p-6">
          <div className="max-w-md text-center space-y-4">
            <h2 className="text-xl font-semibold">Application error</h2>
            <p className="text-sm text-muted-foreground">
              A critical rendering error occurred.
            </p>
            <button
              onClick={() => reset()}
              className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground"
            >
              Reload app
            </button>
            <pre className="text-xs text-left whitespace-pre-wrap break-all p-3 rounded-md bg-muted">
              {error?.message || 'Unknown error'}
            </pre>
          </div>
        </div>
      </body>
    </html>
  );
}
