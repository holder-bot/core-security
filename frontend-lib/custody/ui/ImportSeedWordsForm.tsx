'use client';

import { useMemo, useRef, useState, type ClipboardEvent, type KeyboardEvent } from 'react';
import * as bip39 from 'bip39';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { ArrowLeft } from 'lucide-react';
import { isMultiWordClipboardPaste } from '@/lib/custody/seedConfirm';

type WordCount = 12 | 24;

/**
 * Numbered word boxes for seed import. Multi-word clipboard paste is blocked;
 * Space advances to the next box.
 */
export function ImportSeedWordsForm({
  onBack,
  onSubmit,
  isLoading,
}: {
  onBack: () => void;
  onSubmit: (mnemonic: string) => void | Promise<void>;
  isLoading: boolean;
}) {
  const [wordCount, setWordCount] = useState<WordCount>(12);
  const [words, setWords] = useState<string[]>(() => Array(12).fill(''));
  const [pasteBlockedHint, setPasteBlockedHint] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const inputRefs = useRef<Array<HTMLInputElement | null>>([]);

  const setCount = (next: WordCount) => {
    setWordCount(next);
    setWords((prev) => {
      const nextWords = Array(next).fill('');
      for (let i = 0; i < Math.min(prev.length, next); i++) nextWords[i] = prev[i];
      return nextWords;
    });
  };

  const filled = useMemo(
    () => words.every((w) => w.trim().length > 0),
    [words],
  );

  const updateWord = (index: number, value: string) => {
    const cleaned = value.replace(/\s+/g, '');
    setWords((prev) => {
      const next = [...prev];
      next[index] = cleaned;
      return next;
    });
  };

  const focusWord = (index: number) => {
    const el = inputRefs.current[index];
    if (el) {
      el.focus();
      el.select();
    }
  };

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === ' ' || e.code === 'Space') {
      e.preventDefault();
      if (index < wordCount - 1) focusWord(index + 1);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (index < wordCount - 1) focusWord(index + 1);
      else if (filled) handleSubmit();
      return;
    }
    if (e.key === 'Backspace' && !words[index] && index > 0) {
      e.preventDefault();
      focusWord(index - 1);
    }
  };

  const handlePaste = (index: number, e: ClipboardEvent<HTMLInputElement>) => {
    const text = (e.clipboardData.getData('text') || '').trim();
    if (isMultiWordClipboardPaste(text)) {
      e.preventDefault();
      setPasteBlockedHint(true);
      window.setTimeout(() => setPasteBlockedHint(false), 2500);
      return;
    }
    e.preventDefault();
    updateWord(index, text.split(/\s+/).filter(Boolean)[0] || '');
  };

  const handleSubmit = () => {
    if (!filled) return;
    setValidationError(null);
    const mnemonic = words.map((w) => w.trim().toLowerCase()).join(' ');
    if (!bip39.validateMnemonic(mnemonic)) {
      setValidationError('Invalid seed phrase — check spelling and word count (BIP39).');
      return;
    }
    void onSubmit(mnemonic);
  };

  return (
    <div className="space-y-5" data-testid="import-seed-words-form">
      <div className="flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1 text-sm text-gray-300 hover:text-white"
          data-testid="import-seed-back"
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </button>
        <div className="flex items-center gap-3">
          <span className={`text-sm ${wordCount === 12 ? 'text-white' : 'text-gray-500'}`}>12</span>
          <button
            type="button"
            aria-label="Toggle 12 or 24 words"
            data-testid="import-seed-word-count-toggle"
            onClick={() => setCount(wordCount === 12 ? 24 : 12)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              wordCount === 24 ? 'wallet-button-primary' : 'bg-gray-600'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                wordCount === 24 ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
          <span className={`text-sm ${wordCount === 24 ? 'text-white' : 'text-gray-500'}`}>24</span>
        </div>
      </div>

      <div>
        <Label className="wallet-text-secondary">Enter seed phrase</Label>
        <p className="text-xs text-gray-500 mt-1 mb-3">
          Type each word into its box. Press Space to move to the next word.
        </p>
        <div className="grid grid-cols-2 gap-2">
          {words.map((word, index) => (
            <label
              key={index}
              className="flex items-center gap-1.5 rounded border border-gray-700 bg-gray-900/60 px-2 py-1.5 min-w-0"
            >
              <span className="text-[10px] text-gray-500 w-5 shrink-0">{index + 1}.</span>
              <input
                ref={(el) => {
                  inputRefs.current[index] = el;
                }}
                type="text"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                data-testid={`import-seed-word-${index + 1}`}
                value={word}
                onChange={(e) => updateWord(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                onPaste={(e) => handlePaste(index, e)}
                className="w-full min-w-0 bg-transparent font-mono text-sm text-white outline-none placeholder:text-gray-600"
                placeholder="word"
              />
            </label>
          ))}
        </div>
        {pasteBlockedHint && (
          <p className="text-xs text-amber-400 mt-2" data-testid="import-seed-paste-blocked">
            Enter one word at a time.
          </p>
        )}
      </div>

      {validationError && (
        <p className="text-xs text-red-400" data-testid="import-seed-validation-error">
          {validationError}
        </p>
      )}

      <Button
        onClick={handleSubmit}
        disabled={isLoading || !filled}
        className="w-full wallet-button-primary"
        data-testid="import-seed-submit"
      >
        {isLoading ? 'Importing…' : 'Import Wallet'}
      </Button>
    </div>
  );
}
