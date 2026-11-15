import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const alertVariants = cva(
  "group/alert relative grid w-full gap-1 rounded-lg border-l-4 border-y-0 border-r-0 bg-transparent px-4 py-3 text-left text-sm text-foreground",
  {
    variants: {
      variant: {
        default: "border-l-foreground bg-muted/20",
        destructive: "border-l-[#E30613] bg-muted/20 text-foreground",
        accent: "border-l-[#E30613] bg-muted/20 text-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Alert({
  className,
  variant,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof alertVariants>) {
  return (
    <div
      data-slot="alert"
      role="alert"
      className={cn(alertVariants({ variant }), className)}
      {...props}
    />
  )
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn(
        "font-bold leading-tight tracking-tight text-foreground",
        className
      )}
      {...props}
    />
  )
}

function AlertDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn("text-xs leading-relaxed text-muted-foreground", className)}
      {...props}
    />
  )
}

export { Alert, AlertTitle, AlertDescription }
