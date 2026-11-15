import type { SVGProps } from "react";
import { cn } from "@/lib/utils";

export interface RippleLogoProps extends SVGProps<SVGSVGElement> {
  className?: string;
}

export function RippleLogo({ className, width = 32, height = 32, ...props }: RippleLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 223 232"
      fill="none"
      stroke="currentColor"
      strokeWidth="6"
      role="img"
      aria-label="Ripple"
      width={width}
      height={height}
      className={cn("size-8 w-8 h-8 shrink-0 flex-shrink-0 text-foreground", className)}
      {...props}
    >
      <g fill="currentColor" stroke="none">
        <circle cx="105" cy="33" r="10" />
        <circle cx="62" cy="92" r="24" />
        <circle cx="102" cy="123" r="32" />
        <circle cx="160" cy="155" r="18" />
        <circle cx="97" cy="192" r="13" />
      </g>
      <circle cx="105" cy="33" r="20" />
      <circle cx="62" cy="92" r="35" />
      <circle cx="62" cy="92" r="48" />
      <circle cx="102" cy="123" r="44" />
      <circle cx="102" cy="123" r="57" />
      <circle cx="102" cy="116" r="76" />
      <circle cx="160" cy="155" r="30" />
      <circle cx="160" cy="155" r="42" />
      <circle cx="97" cy="192" r="25" />
    </svg>
  );
}
