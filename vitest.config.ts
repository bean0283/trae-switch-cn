import { defineConfig } from "vitest/config";
import path from "node:path";

// 独立于 vite.config.ts：那份是异步函数式 defineConfig，且带 Tauri 专用的
// server / base 配置，测试用不上。这里只保留测试真正需要的两件事：
// @ 别名（与 vite.config.ts 保持一致）与测试文件匹配规则。
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    // 首批只覆盖纯逻辑模块（无 DOM 依赖），node 环境足够且启动最快。
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
