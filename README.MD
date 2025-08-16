# CobaltStrike Beacon Source Code  / CobaltStrike Beacon 源代码 （正在改进，实现现代化免杀，模块改进）
# [原仓库](https://github.com/kyxiaxiang/CobaltStrikeBeaconCppSource)已被DMCA TAKEDOWN(https://github.com/Basyaact/CobaltStrikeBeaconDLLSourceLeaked-CSVersion2022-4.5/blob/main/DMCA2025-08-1615.51.48.png).
[English](#english) | [中文](#chinese)

## English

This repository contains the source code of CobaltStrike's Beacon, which is ready to use out of the box. I purchased this from China's Xianyu trading platform.

> **Note:** This branch is a cross-compiled version for **macOS**. For the Windows version, please check the [Windows branch](https://github.com/kyxiaxiang/CobaltStrikeBeaconCppSource).  
> This repository contains a ready-to-use **Cobalt Strike Beacon DLL** source code, purchased from the Chinese Xianyu trading platform.  
> Special thanks to the original author [@kyxiaxiang](https://github.com/kyxiaxiang) for the selfless contribution.

---

## 📜 Source

In 2022, the source code of the **Cobalt Strike 4.5 Beacon DLL** suddenly began circulating in underground Telegram channels.  
It was later sold at high prices—up to **3,500 RMB**—on Chinese second-hand platforms.  

This commercialized leak not only reflects the **strong demand for red team tools** but also exposes the risks of **weaponizing closed-source security software**.  

Now, with parts of the Beacon code made public, the security community finally has the opportunity to analyze its key techniques at the source level—such as:

- Thread injection
- Sleep obfuscation
- C2 communications

This marks a milestone for both **enhancing blue team detection capabilities** and **advancing the evolution of red team tools**.

---

## ❓ Why Share? *(Original Author’s Words)*

> I decided to make this source code public because I’m tired of seeing people indirectly selling the Beacon source code in various ways for profit.  
> While this repository may eventually face a **DMCA takedown**, I believe that *when a whale falls, all creatures thrive* — everyone should have the chance to learn.  
>   
> I despise the shameless, repetitive cash-grabbing behavior some people have engaged in over the years. It’s time to end this cycle.

---

## 📦 Dependencies

Using this source code requires:

1. [LibTomMath](https://github.com/libtom/libtommath)
2. [LibTomCrypt](https://github.com/libtom/libtomcrypt)
3. Manually decompile the JAR file
4. Replace the DLL file accordingly

> **Note:** Related dependency installation and compilation scripts can be executed in one step.  
> See [`install_lib.sh`](./install_lib.sh) for details.

---

## 🎯 Purpose

I hope this code can:

1. Provide reference and suggestions for more open-source C2 projects
2. Promote the maturity of more open-source projects
3. Help improve AV/EDR detection capabilities
4. Contribute to cybersecurity

💡 Dedicated to all **red** and **blue** teams.

---

## ⚠️ Disclaimer / 免责声明

**This code is for educational and research purposes only.**  
The author assumes no responsibility for any misuse.

# 声明：这个仓库随时会被DMCA TAKEDOWN，请尽快Clone. 
# due to the nature of this repository, it may be subject to DMCA takedown at any time. Please clone it as soon as possible.
## Chinese
注意：此版本为macOS版本的交叉编译分支，Windows版本请查看[Windows分支](https://github.com/kyxiaxiang/CobaltStrikeBeaconCppSource)
这个仓库包含了开箱即用的CobaltStrike Beacon DLL源代码，购买自中国闲鱼交易平台（在此感谢原作者@kyxiaxiang的无私贡献)。

### 来源
2022年CobaltStrike 4.5版本的Beacon DLL源码突然在Telegram黑产渠道流传，随后甚至在中国二手平台标价3500元高价流通，这种商业化泄露既反映了红队工具的旺盛需求，也暴露出闭源安全软件被武器化的风险。如今随着部分Beacon代码的公开，安全社区终于有机会从源码层面剖析其线程注入、睡眠混淆、C2通信等关键技术，这对提升蓝队检测能力和推动红队工具进化都具有里程碑意义。

### 为什么要分享？(原作者原文)

我决定公开这份源码，因为我看不惯一些人通过各种方式变相售卖Beacon源码来牟利。虽然这个仓库未来可能会面临DMCA下架，但我相信一鲸落万物生 - 每个人都应该有学习的机会。

我很鄙夷某些人这些年来恬不知耻、反反复复的圈钱行为。是时候结束这个循环了。

### 依赖项

使用这份源码需要：
1. 准备 [LibTomMath](https://github.com/libtom/libtommath)
2. 准备 [LibTomCrypt](https://github.com/libtom/libtomcrypt)
3. 自行反编译jar文件
4. 相应替换DLL文件
注：相关依赖库安装以及编译的脚本可一键完成，具体请查看[install_lib.sh]
### 目的

希望这份代码能够：
1. 为更多的开源C2项目提供参考建议
2. 促进更多开源项目的成熟
3. 帮助提升AV/EDR的检测能力
4. 为网络安全做出贡献

献给各位红蓝队。

---

## Disclaimer / 免责声明

This code is for educational and research purposes only. The author assumes no responsibility for any misuse.

本代码仅用于教育和研究目的。作者对任何滥用行为不承担责任。
