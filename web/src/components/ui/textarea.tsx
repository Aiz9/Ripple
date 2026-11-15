import * as React from "react"

import { cn } from "@/lib/utils"

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "flex field-sizing-content max-h-[45vh] min-h-20 w-full overflow-auto rounded-lg border border-input bg-transparent px-3 py-2 text-sm text-foreground transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-[#E30613] disabled:cursor-not-allowed disabled:opacity-40",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
