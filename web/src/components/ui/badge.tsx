import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "group/badge inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider tabular-nums transition-colors [&>svg]:pointer-events-none [&>svg]:size-3!",
  {
    variants: {
      variant: {
        default:
          "border-foreground bg-foreground text-background",
        secondary:
          "border-border bg-secondary text-secondary-foreground",
        destructive:
          "border-[#E30613] bg-[#E30613] text-white",
        outline:
          "border-border bg-transparent text-foreground",
        accent:
          "border-[#E30613] bg-transparent text-[#E30613]",
        ghost:
          "border-transparent bg-transparent text-muted-foreground",
        link:
          "border-transparent text-foreground underline-offset-4 hover:underline normal-case",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "span"

  return (
    <Comp
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  )
}

export { Badge, badgeVariants }
