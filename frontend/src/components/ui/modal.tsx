"use client";

import React, { useEffect } from "react";
import { X } from "lucide-react";

interface ModalProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: React.ReactNode;
  maxWidthClass?: string;
}

export function Modal({
  open,
  title,
  description,
  onClose,
  children,
  maxWidthClass = "max-w-lg",
}: ModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-[1px] p-4"
    >
      <div
        className={`w-full ${maxWidthClass} rounded-lg border border-soc-border bg-soc-surface shadow-2xl overflow-hidden`}
      >
        <div className="flex items-start justify-between border-b border-soc-border px-5 py-4">
          <div>
            <h2 id="modal-title" className="text-base font-semibold text-soc-text">
              {title}
            </h2>
            {description && <p className="text-xs text-soc-muted mt-0.5">{description}</p>}
          </div>
          <button
            type="button"
            aria-label="Close dialog"
            onClick={onClose}
            className="rounded p-1 text-soc-muted hover:bg-soc-elevated hover:text-soc-text"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 max-h-[80vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

