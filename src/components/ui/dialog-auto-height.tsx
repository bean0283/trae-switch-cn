import { useLayoutEffect, useRef, useState, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Radix 负责弹窗行为，共享 Dialog 样式负责缩放；这里只补充内容尺寸过渡。
 * 测量自然布局的内层，动画作用于外层，避免高度写入反过来影响测量。
 * 内层不要使用依赖外层高度的 h-full；滚动上限由内容自身的 max-height 控制。
 */
export function DialogAutoHeight({ children, className }: { children: ReactNode; className?: string }) {
  const contentRef = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState<number>();

  useLayoutEffect(() => {
    const content = contentRef.current;
    if (!content) return;
    // offsetHeight 不受祖先入场缩放影响；首帧 auto → 实际高度无需过渡。
    const measure = () => setHeight(content.offsetHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(content);
    return () => observer.disconnect();
  }, []);

  return (
    <div data-slot="dialog-auto-height" className={cn("min-h-0 shrink-0 overflow-hidden transition-[height] duration-200 ease-out motion-reduce:transition-none", className)} style={{ height }}>
      <div ref={contentRef} className="flow-root">{children}</div>
    </div>
  );
}
