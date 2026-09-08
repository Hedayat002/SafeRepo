'use client';

import React, { useState } from 'react';
import type { FindingResponseData } from '@/types';
import { Badge } from '@/components/ui/Badge';
import { RemediationPanel } from './RemediationPanel';

export interface FindingRowProps {
  finding: FindingResponseData;
}

export function FindingRow({ finding }: FindingRowProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const fileLocation =
    finding.line > 0
      ? `${finding.file}:${finding.line}`
      : finding.file;

  return (
    <div className="border-b border-gray-200 dark:border-gray-800 last:border-b-0 transition-colors">
      {/* Header / Clickable Summary Row */}
      <button
        type="button"
        onClick={() => setIsExpanded(!isExpanded)}
        aria-expanded={isExpanded}
        className="w-full text-left p-4 hover:bg-gray-50/70 dark:hover:bg-gray-800/40 flex items-start gap-3 transition-colors focus:outline-none focus:bg-gray-50/80 dark:focus:bg-gray-800/50"
      >
        <div className="pt-0.5 flex-shrink-0">
          <Badge variant={finding.severity} size="sm">
            {finding.severity.toUpperCase()}
          </Badge>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">
              {finding.title}
            </h4>
            <span className="text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 font-mono">
              {finding.category}
            </span>
            <span className="text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 font-mono">
              {finding.scanner}
            </span>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate">
            {fileLocation}
          </div>
        </div>

        <div className="flex-shrink-0 text-gray-400 dark:text-gray-500 pt-1">
          <svg
            className={`w-4 h-4 transform transition-transform duration-200 ${
              isExpanded ? 'rotate-180' : ''
            }`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </div>
      </button>

      {/* Expanded Details Drawer */}
      {isExpanded && (
        <div className="p-4 pt-0 bg-gray-50/40 dark:bg-gray-850/40 flex flex-col gap-4 text-xs">
          {/* Detailed Description */}
          {finding.description && (
            <div>
              <span className="font-semibold text-gray-700 dark:text-gray-300 block mb-1">
                Description:
              </span>
              <p className="text-gray-600 dark:text-gray-400 leading-relaxed">
                {finding.description}
              </p>
            </div>
          )}

          {/* Code Snippet (if available) - XSS Safe: rendered as text */}
          {finding.codeSnippet && (
            <div>
              <span className="font-semibold text-gray-700 dark:text-gray-300 block mb-1">
                Vulnerable Code Snippet ({fileLocation}):
              </span>
              <pre className="overflow-x-auto rounded-lg border border-gray-200 bg-gray-900 p-3 font-mono text-xs text-gray-100 dark:border-gray-700">
                <code>{finding.codeSnippet}</code>
              </pre>
            </div>
          )}

          {/* Remediation Guidance Panel */}
          <RemediationPanel finding={finding} />
        </div>
      )}
    </div>
  );
}
