'use client';

import type { CSSProperties, SyntheticEvent } from 'react';

/**
 * Display a mnemonic without allowing select / copy / cut / context-menu.
 * Used after wallet create and on settings seed recovery.
 */
export function ProtectedSeedPhrase({
  seedPhrase,
  className = '',
}: {
  seedPhrase: string;
  className?: string;
}) {
  const words = seedPhrase.trim().split(/\s+/).filter(Boolean);

  const block = (e: SyntheticEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <div
      className={`select-none ${className}`}
      data-testid="protected-seed-phrase"
      onCopy={block}
      onCut={block}
      onPaste={block}
      onContextMenu={block}
      style={{ userSelect: 'none', WebkitUserSelect: 'none' } as CSSProperties}
    >
      <div className="grid grid-cols-2 gap-2">
        {words.map((word, index) => (
          <div
            key={`${index}-${word}`}
            className="flex items-start gap-2 rounded border border-gray-700 bg-gray-900/80 px-2.5 py-2 font-mono text-sm text-white min-w-0"
          >
            <span className="text-[10px] text-gray-500 w-5 shrink-0 pt-0.5">{index + 1}.</span>
            <span className="break-all whitespace-normal leading-snug">{word}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
