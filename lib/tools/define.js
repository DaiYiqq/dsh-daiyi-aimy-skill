/**
 * 宿主工具定义的唯一入口。
 *
 * `defineTool` 由 DeepSeek Harness 运行时提供（peer dependency），这里单独 re-export，
 * 让每个工具模块只依赖本文件：契约测试可以用同样的入口替换成宿主解包副本，
 * 生产环境则由宿主解析 `@deepseek-ai/dsh-tools`。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/define
 */

export { defineTool } from '@deepseek-ai/dsh-tools'
