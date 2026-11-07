# codex-vmprotect-unpack-skill
用于 ChatGPT-Codex 的 VMProtect 解包技能

# 此Skill可以做什么
去除VMProtect加密后的调试器检测以及虚拟机检测，并还原被加密的IAT表以及字符串

# 支持解包的VMProtect版本范围
理论支持 VMProtect **3.5.0 - 3.10.4(或更高版本)** 加密的 x64/x86 Exe/Dll

仓库内样例程序通过此Skill成功解包的VMProtect版本列表：

VMProtect 3.5.0 Ultimate x64/x86

VMProtect 3.8.4 Ultimate x64

VMProtect 3.8.7 Ultimate x64

VMProtect 3.9.4 Ultimate x64

VMProtect 3.10.3 Professional x64

VMProtect 3.10.4 Lite x64/x86

# 使用
打包仓库内Skill文件为ZIP后通过CCSwitch导入或直接放入 ~/.codex/skills 中

此Skill同样也支持Claude使用

# 说明
本Skill仅能保证解包VMProtect保护 无法保证还原虚拟化代码以及变异代码

解包后的产物去除了VMProtect的调试器检测以及虚拟机检测 故可以正常在本地设备以及虚拟机上运行以及调试

此Skill通过 **GPT-6 Astra** 生成

用于脱壳训练Skill的样本程序为仓库内的 ConsoleApp2Cpp 作为样例

# 鸣谢
[@Zopiclone-main](https://github.com/Zopiclone-main)
