import type { ButtonHTMLAttributes, InputHTMLAttributes, TextareaHTMLAttributes } from "react";

// Small, dependency-free Tailwind primitives in a shadcn-like style
// (consistent spacing/radius/focus-ring conventions) -- deliberately
// hand-rolled rather than installed from a component library, since this
// console only ever needs a handful of them.

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}) {
  const base =
    "inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium " +
    "transition-colors focus-visible:outline-none focus-visible:ring-2 " +
    "focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50";
  const variants: Record<string, string> = {
    primary: "bg-slate-900 text-white hover:bg-slate-700 focus-visible:ring-slate-900",
    secondary:
      "bg-white text-slate-900 border border-slate-300 hover:bg-slate-50 " +
      "focus-visible:ring-slate-400",
    danger: "bg-red-600 text-white hover:bg-red-500 focus-visible:ring-red-600",
    ghost: "text-slate-600 hover:bg-slate-100 focus-visible:ring-slate-300",
  };
  return <button className={`${base} ${variants[variant]} ${className}`} {...props} />;
}

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-lg border border-slate-200 bg-white shadow-sm ${className}`}>
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-slate-200 px-4 py-3">
      <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
      {subtitle ? <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p> : null}
    </div>
  );
}

export function Badge({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium " +
        className
      }
    >
      {children}
    </span>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={
        "block w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm " +
        "focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500 " +
        (props.className ?? "")
      }
    />
  );
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={
        "block w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm " +
        "focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500 " +
        (props.className ?? "")
      }
    />
  );
}
