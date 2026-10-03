import * as React from "react";
import * as PopoverPrimitive from "@radix-ui/react-popover";

import { cn } from "@/lib/utils";
import "./popover.css";

function Popover({ ...props }: React.ComponentProps<typeof PopoverPrimitive.Root>) {
  return <PopoverPrimitive.Root data-slot="popover" {...props} />;
}

function PopoverTrigger({ className, ...props }: React.ComponentProps<typeof PopoverPrimitive.Trigger>) {
  // Tailwind v4 preflight makes <button> cursor:default; a wrapper trigger that is not
  // composed with an owned Button still has to show the hand cursor.
  return <PopoverPrimitive.Trigger data-slot="popover-trigger" className={cn("cursor-pointer", className)} {...props} />;
}

function PopoverAnchor({ ...props }: React.ComponentProps<typeof PopoverPrimitive.Anchor>) {
  return <PopoverPrimitive.Anchor data-slot="popover-anchor" {...props} />;
}

function PopoverContent({
  className,
  align = "center",
  sideOffset = 4,
  collisionPadding = 8,
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal data-slot="popover-portal">
      <PopoverPrimitive.Content
        data-slot="popover-content"
        align={align}
        sideOffset={sideOffset}
        collisionPadding={collisionPadding}
        className={cn(
          "bg-popover text-popover-foreground z-50 w-72 origin-(--radix-popover-content-transform-origin) rounded-lg p-4 shadow-lg ring-1 ring-black/5 outline-hidden data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}

function PopoverArrow({ className, ...props }: React.ComponentProps<typeof PopoverPrimitive.Arrow>) {
  // Rotated square in the popover color: radix reserves the arrow's measured height as extra
  // content offset, so the visible tip stays outside the panel and keeps the sideOffset gap.
  // `border-black/5` matches the panel ring; the exposed two edges get their width from
  // `popover.css` (keyed on the Content `data-side`), so the outline stays continuous.
  const arrowClassName = "bg-popover fill-popover border-black/5 z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px]";
  return <PopoverPrimitive.Arrow data-slot="popover-arrow" className={cn(arrowClassName, className)} {...props} />;
}

export { Popover, PopoverAnchor, PopoverArrow, PopoverContent, PopoverTrigger };
