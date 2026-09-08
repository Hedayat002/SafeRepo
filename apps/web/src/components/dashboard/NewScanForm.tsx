'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';

export interface RepoOption {
  id: number;
  name: string;
  fullName: string;
  owner: string;
  defaultBranch?: string;
}

export interface NewScanFormProps {
  initialRepos?: RepoOption[];
}

export function NewScanForm({ initialRepos = [] }: NewScanFormProps) {
  const router = useRouter();

  const [repos, setRepos] = useState<RepoOption[]>(initialRepos);
  const [loadingRepos, setLoadingRepos] = useState(initialRepos.length === 0);
  const [repoError, setRepoError] = useState<string | null>(null);

  const [selectedRepoFullName, setSelectedRepoFullName] = useState<string>('');
  const [customOwner, setCustomOwner] = useState<string>('');
  const [customName, setCustomName] = useState<string>('');
  const [branch, setBranch] = useState<string>('');
  const [isManualInput, setIsManualInput] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Fetch GitHub repos on client mount if initialRepos was empty
  useEffect(() => {
    if (initialRepos.length > 0) return;

    let isMounted = true;
    const fetchRepos = async () => {
      try {
        setLoadingRepos(true);
        setRepoError(null);
        const res = await fetch('/api/v1/repos?per_page=100', {
          headers: { Accept: 'application/json' },
          credentials: 'include',
        });

        if (!res.ok) {
          throw new Error(`Failed to load GitHub repositories (HTTP ${res.status})`);
        }

        const json = await res.json();
        if (isMounted) {
          const loadedRepos: RepoOption[] = (json.data ?? []).map(
            (r: { id: number; name: string; fullName: string; owner: string; defaultBranch?: string }) => ({
              id: r.id,
              name: r.name,
              fullName: r.fullName,
              owner: r.owner,
              defaultBranch: r.defaultBranch,
            })
          );
          setRepos(loadedRepos);
          if (loadedRepos.length > 0) {
            setSelectedRepoFullName(loadedRepos[0].fullName);
            setBranch(loadedRepos[0].defaultBranch || 'main');
          }
        }
      } catch (err: unknown) {
        if (isMounted) {
          setRepoError(
            err instanceof Error ? err.message : 'Failed to fetch repositories'
          );
          setIsManualInput(true);
        }
      } finally {
        if (isMounted) setLoadingRepos(false);
      }
    };

    fetchRepos();

    return () => {
      isMounted = false;
    };
  }, [initialRepos.length]);

  const handleRepoSelectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const fullName = e.target.value;
    setSelectedRepoFullName(fullName);

    const found = repos.find((r) => r.fullName === fullName);
    if (found?.defaultBranch) {
      setBranch(found.defaultBranch);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);

    let repositoryOwner = '';
    let repositoryName = '';

    if (isManualInput) {
      repositoryOwner = customOwner.trim();
      repositoryName = customName.trim();
    } else {
      const parts = selectedRepoFullName.split('/');
      if (parts.length === 2) {
        repositoryOwner = parts[0];
        repositoryName = parts[1];
      }
    }

    if (!repositoryOwner || !repositoryName) {
      setSubmitError('Repository owner and name are required.');
      return;
    }

    setIsSubmitting(true);

    try {
      const res = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          repositoryOwner,
          repositoryName,
          branch: branch.trim() || undefined,
        }),
      });

      if (res.status === 429) {
        throw new Error(
          'Too many scan requests. Please wait a few moments before trying again.'
        );
      }

      const json = await res.json();

      if (!res.ok) {
        throw new Error(
          json.error?.message || `Failed to initiate scan (HTTP ${res.status})`
        );
      }

      const createdScan = json.data;
      if (createdScan?.id) {
        router.push(`/dashboard/scans/${createdScan.id}`);
      } else {
        router.push('/dashboard');
      }
    } catch (err: unknown) {
      setSubmitError(
        err instanceof Error ? err.message : 'An error occurred while creating scan'
      );
      setIsSubmitting(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-800 dark:bg-gray-900 flex flex-col gap-6"
    >
      <div className="border-b border-gray-100 pb-4 dark:border-gray-800">
        <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100">
          Run Security Scan
        </h2>
        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
          Select an authorized GitHub repository to inspect for security vulnerabilities, secrets, and dependency issues.
        </p>
      </div>

      {submitError && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 p-4 text-xs text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
        >
          {submitError}
        </div>
      )}

      {/* Repo Selection or Manual Input */}
      {!isManualInput ? (
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label
              htmlFor="repo-select"
              className="text-xs font-semibold text-gray-700 dark:text-gray-300"
            >
              Select Repository
            </label>
            <button
              type="button"
              onClick={() => setIsManualInput(true)}
              className="text-xs text-blue-600 hover:underline dark:text-blue-400"
            >
              Enter repository manually
            </button>
          </div>

          {loadingRepos ? (
            <div className="flex items-center gap-2 py-3 px-4 border rounded-lg text-xs text-gray-500 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
              <Spinner size="sm" label="Loading repositories from GitHub..." />
              <span>Fetching repositories from GitHub...</span>
            </div>
          ) : repos.length > 0 ? (
            <select
              id="repo-select"
              value={selectedRepoFullName}
              onChange={handleRepoSelectChange}
              disabled={isSubmitting}
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            >
              {repos.map((r) => (
                <option key={r.id} value={r.fullName}>
                  {r.fullName}
                </option>
              ))}
            </select>
          ) : (
            <div className="p-3 border rounded-lg text-xs text-gray-500 dark:border-gray-700">
              No repositories found. Ensure your GitHub App has repository access.
            </div>
          )}

          {repoError && (
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
              Note: {repoError}
            </p>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">
              Manual Repository Input
            </span>
            {repos.length > 0 && (
              <button
                type="button"
                onClick={() => setIsManualInput(false)}
                className="text-xs text-blue-600 hover:underline dark:text-blue-400"
              >
                Back to repository list
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <label
                htmlFor="custom-owner"
                className="text-xs font-medium text-gray-600 dark:text-gray-400"
              >
                Repository Owner (User / Org)
              </label>
              <input
                id="custom-owner"
                type="text"
                placeholder="e.g. facebook"
                value={customOwner}
                onChange={(e) => setCustomOwner(e.target.value)}
                disabled={isSubmitting}
                className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label
                htmlFor="custom-name"
                className="text-xs font-medium text-gray-600 dark:text-gray-400"
              >
                Repository Name
              </label>
              <input
                id="custom-name"
                type="text"
                placeholder="e.g. react"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                disabled={isSubmitting}
                className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
          </div>
        </div>
      )}

      {/* Branch input */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor="scan-branch"
          className="text-xs font-semibold text-gray-700 dark:text-gray-300"
        >
          Branch Name (optional)
        </label>
        <input
          id="scan-branch"
          type="text"
          placeholder="main"
          value={branch}
          onChange={(e) => setBranch(e.target.value)}
          disabled={isSubmitting}
          className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        />
        <span className="text-xs text-gray-400 dark:text-gray-500">
          Leave blank to scan the default branch.
        </span>
      </div>

      <div className="pt-4 border-t border-gray-100 dark:border-gray-800 flex items-center justify-end gap-3">
        <button
          type="button"
          onClick={() => router.back()}
          disabled={isSubmitting}
          className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
        >
          Cancel
        </button>
        <Button
          type="submit"
          loading={isSubmitting}
          disabled={isSubmitting}
          variant="primary"
          size="md"
        >
          {isSubmitting ? 'Initiating scan...' : 'Start Security Scan'}
        </Button>
      </div>
    </form>
  );
}
