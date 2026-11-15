import * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 rounded-lg border border-input bg-transparent px-3 py-1.5 text-sm text-foreground transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-[#E30613] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-40",
        className
      )}
      {...props}
    />
  )
}

export { Input }
