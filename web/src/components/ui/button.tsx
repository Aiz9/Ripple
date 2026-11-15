import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-lg border border-transparent text-sm font-medium whitespace-nowrap uppercase tracking-wider transition-colors outline-none select-none disabled:pointer-events-none disabled:opacity-40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
  {
    variants: {
      variant: {
        default:
          "border-primary bg-primary text-primary-foreground hover:bg-background hover:text-foreground hover:border-foreground",
        accent:
          "border-[#E30613] bg-[#E30613] text-white hover:bg-black hover:border-black dark:hover:bg-white dark:hover:text-black",
        outline:
          "border-foreground bg-transparent text-foreground hover:bg-foreground hover:text-background",
        secondary:
          "border-border bg-secondary text-secondary-foreground hover:border-foreground hover:bg-foreground hover:text-background",
        ghost:
          "border-transparent bg-transparent text-foreground hover:bg-muted hover:border-border",
        destructive:
          "border-[#E30613] bg-transparent text-[#E30613] hover:bg-[#E30613] hover:text-white",
        link:
          "border-transparent bg-transparent text-foreground underline-offset-4 hover:underline lowercase normal-case tracking-normal",
      },
      size: {
        default: "h-9 gap-2 px-4 text-xs font-semibold",
        xs: "h-6 gap-1 px-2 text-[10px] font-semibold",
        sm: "h-7 gap-1.5 px-3 text-[11px] font-semibold",
        lg: "h-11 gap-2.5 px-6 text-sm font-semibold",
        icon: "size-9 p-0",
        "icon-xs": "size-6 p-0",
        "icon-sm": "size-7 p-0",
        "icon-lg": "size-11 p-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
