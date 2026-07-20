'use client';

import { useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { AlertTriangle, Sprout } from 'lucide-react';
import { BrandHeader } from '@/components/shared/BrandHeader';
import { ProtectedSeedPhrase } from '@/components/wallet/ProtectedSeedPhrase';
import {
  answersMatchChallenges,
  isMultiWordClipboardPaste,
  pickSeedChallenges,
  splitMnemonicWords,
  type SeedChallenge,
} from '@/lib/custody/seedConfirm';

interface SeedPhraseScreenProps {
  seedPhrase: string;
  onContinue: () => void;
  systemLog?: { logInfo?: (msg: string) => void };
}

export default function SeedBackupScreen({
  seedPhrase,
  onContinue,
  systemLog,
}: SeedPhraseScreenProps) {
  const words = useMemo(() => splitMnemonicWords(seedPhrase), [seedPhrase]);
  const [step, setStep] = useState<'show' | 'confirm'>('show');
  const [challenges, setChallenges] = useState<SeedChallenge[]>([]);
  const [answers, setAnswers] = useState<string[]>(['', '']);
  const [confirmError, setConfirmError] = useState<string | null>(null);

  const handleContinueToConfirm = () => {
    setChallenges(pickSeedChallenges(words));
    setAnswers(['', '']);
    setConfirmError(null);
    setStep('confirm');
  };

  const handleConfirm = () => {
    if (!answersMatchChallenges(challenges, answers)) {
      setConfirmError('Words do not match. Check your written backup and try again.');
      return;
    }
    systemLog?.logInfo?.('Seed phrase confirmed via word challenge, proceeding to wallet');
    onContinue();
  };

  return (
    <div className="min-h-screen wallet-bg-primary wallet-text-primary font-mono">
      <div className="mx-auto w-full max-w-[380px] px-4 py-4">
        <BrandHeader hideMenu />

        <Card className="wallet-card bg-gray-950 border-gray-700/50 mt-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-semibold text-gray-300 flex items-center gap-2">
              <Sprout className="w-4 h-4 text-blue-500" />
              {step === 'show' ? 'Save your seed phrase' : 'Confirm your seed phrase'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            {step === 'show' ? (
              <>
                <Alert className="border-yellow-400/30 bg-yellow-400/10">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                  <AlertDescription className="text-yellow-400 text-sm">
                    Write these {words.length} words down and store them offline. This is the only way
                    to recover your wallet.
                  </AlertDescription>
                </Alert>

                <ProtectedSeedPhrase seedPhrase={seedPhrase} />

                <ul className="text-xs text-gray-500 space-y-1 list-disc list-inside">
                  <li>Write down all words in order</li>
                  <li>Never share them with anyone</li>
                  <li>You will confirm two words before continuing</li>
                </ul>

                <Button
                  onClick={handleContinueToConfirm}
                  className="w-full wallet-button-primary"
                  data-testid="seed-backup-continue"
                >
                  I&apos;ve written it down
                </Button>
              </>
            ) : (
              <>
                <p className="text-sm text-gray-400">
                  Enter the requested words from your backup to confirm you saved them.
                </p>
                <div className="space-y-3">
                  {challenges.map((c, i) => (
                    <div key={c.index} className="space-y-1.5">
                      <Label className="wallet-text-secondary" htmlFor={`seed-confirm-${c.index}`}>
                        Word #{c.index + 1}
                      </Label>
                      <Input
                        id={`seed-confirm-${c.index}`}
                        data-testid={`seed-confirm-word-${c.index + 1}`}
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        value={answers[i] || ''}
                        onChange={(e) => {
                          const next = [...answers];
                          next[i] = e.target.value.replace(/\s+/g, '');
                          setAnswers(next);
                          setConfirmError(null);
                        }}
                        onPaste={(e) => {
                          const text = e.clipboardData.getData('text') || '';
                          if (isMultiWordClipboardPaste(text)) e.preventDefault();
                        }}
                        className="wallet-input font-mono bg-gray-900 text-white border-gray-600"
                        placeholder="word"
                      />
                    </div>
                  ))}
                </div>
                {confirmError && (
                  <p className="text-red-400 text-sm" data-testid="seed-confirm-error">
                    {confirmError}
                  </p>
                )}
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setStep('show')}
                    className="flex-1"
                    data-testid="seed-confirm-back"
                  >
                    Back
                  </Button>
                  <Button
                    onClick={handleConfirm}
                    className="flex-1 wallet-button-primary"
                    data-testid="seed-confirm-submit"
                    disabled={answers.some((a) => !a.trim())}
                  >
                    Confirm
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
