# 第三方组件与许可证（Third-Party Notices）

> 适用：随 FAEVault Android（`app.fae.vault`）APK 分发的第三方组件。
> 来源：本应用的 CycloneDX SBOM，取 **release 运行时类路径的实际解析结果**（含版本冲突收敛后的最终版本）。
> 复现：

```powershell
.\gradlew.bat :app:cyclonedxDirectBom      # → app/build/reports/cyclonedx-direct/bom.json
.\gradlew.bat :app:dependencies --configuration releaseRuntimeClasspath   # 核对哪些组件真的进包
```

当前随包分发 **194 个** 组件。

## 1. 按许可证汇总

| 许可证 | 组件数 | 主要来源 |
|---|---|---|
| Apache-2.0 | 166 | AndroidX / Jetpack Compose / Kotlin 与 kotlinx / OkHttp 与 Okio 等 |
| ML Kit Terms of Service | 9 | Google ML Kit（本应用仅用于端上文字识别 OCR） |
| BSD-2-Clause | 8 | zstd-jni、commonmark 及其 6 个扩展 |
| Android Software Development Kit License | 4 | Google Play Services 基础库（由 ML Kit 引入） |
| Bouncy Castle Licence | 3 | bcprov / bcpkix / bcutil |
| MIT | 2 | zxcvbn、autolink |
| Apache-2.0 / BSD-3-Clause | 1 | androidx.camera:camera-core |
| 无上游声明 | 1 | org.opencv:opencv —— 实为 Apache-2.0，见第 3 节 |

## 2. 非 Apache-2.0 组件明细

| 组件 | 版本 | 许可证 | 官方文本 |
|---|---|---|---|
| `androidx.camera:camera-core` | 1.4.0 | Apache-2.0/BSD-3-Clause | — |
| `com.github.luben:zstd-jni` | 1.5.7-11 | BSD-2-Clause | — |
| `com.google.android.gms:play-services-base` | 18.5.0 | Android Software Development Kit License | https://developer.android.com/studio/terms.html |
| `com.google.android.gms:play-services-basement` | 18.4.0 | Android Software Development Kit License | https://developer.android.com/studio/terms.html |
| `com.google.android.gms:play-services-mlkit-text-recognition-chinese` | 16.0.1 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.android.gms:play-services-mlkit-text-recognition-common` | 19.1.0 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.android.gms:play-services-mlkit-text-recognition` | 19.0.1 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.android.gms:play-services-tasks` | 18.2.0 | Android Software Development Kit License | https://developer.android.com/studio/terms.html |
| `com.google.android.odml:image` | 1.0.0-beta1 | Android Software Development Kit License | https://developer.android.com/studio/terms.html |
| `com.google.mlkit:common` | 18.11.0 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.mlkit:text-recognition-bundled-common` | 17.0.0 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.mlkit:text-recognition-chinese` | 16.0.1 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.mlkit:text-recognition` | 16.0.1 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.mlkit:vision-common` | 17.3.0 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.google.mlkit:vision-interfaces` | 16.3.0 | ML Kit Terms of Service | https://developers.google.com/ml-kit/terms |
| `com.nulab-inc:zxcvbn` | 1.9.0 | MIT | https://opensource.org/license/mit/ |
| `org.bouncycastle:bcpkix-jdk18on` | 1.84 | Bouncy Castle Licence | https://www.bouncycastle.org/licence.html |
| `org.bouncycastle:bcprov-jdk18on` | 1.84 | Bouncy Castle Licence | https://www.bouncycastle.org/licence.html |
| `org.bouncycastle:bcutil-jdk18on` | 1.84 | Bouncy Castle Licence | https://www.bouncycastle.org/licence.html |
| `org.commonmark:commonmark-ext-autolink` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark-ext-footnotes` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark-ext-gfm-strikethrough` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark-ext-gfm-tables` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark-ext-ins` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark-ext-task-list-items` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.commonmark:commonmark` | 0.24.0 | BSD-2-Clause | https://opensource.org/licenses/BSD-2-Clause |
| `org.nibor.autolink:autolink` | 0.11.0 | MIT | https://opensource.org/license/mit/ |
| `org.opencv:opencv` | 4.12.0 | 无上游声明 | — |

## 3. OpenCV 的许可证说明

`org.opencv:opencv:4.12.0` 的 POM 与 AAR **均未声明许可证**，因此 SBOM 把它列为「无上游声明」。
OpenCV 自 4.5.0 起采用 **Apache License 2.0**（4.12.0 适用），本文件即为其授权记录。
（此前该文本单独存放于 `app/src/main/assets/licenses/OpenCV-4.12.0.txt`，现已合并到本文件统一维护。）

## 4. Apache-2.0 组件（166 个）

按 group 家族分布（完整清单见 SBOM）：

| 家族 | 数量 |
|---|---|
| org.jetbrains（Kotlin 标准库、kotlinx 协程/序列化、Compose Multiplatform 注解与 runtime） | 35 |
| androidx.compose（Compose UI / Foundation / Material3 / Animation） | 33 |
| androidx.lifecycle | 20 |
| com.google（datatransport、protobuf-lite 等，均以 Apache-2.0 发布） | 10 |
| androidx.camera | 4 |
| androidx.room / androidx.sqlite | 4 / 4 |
| androidx.activity / annotation / collection / core | 各 3 |
| com.squareup（OkHttp 与 Okio） | 3 |
| 其余 androidx / org.jspecify / 其他 | 其余 |

## 5. 仅构建与测试期使用，**不随 APK 分发**

下列组件出现在 SBOM 中，但 **不在 release 运行时类路径上**（已用第 1 节的命令核验），
因此其许可证义务不适用于本应用的对外分发：

| 组件 | 版本 | 许可证 |
|---|---|---|
| `junit:junit` | 4.13.2 | EPL-1.0 |
| `net.java.dev.jna:jna` / `jna-platform` | 5.6.0 | LGPL-2.1-only / Apache-2.0 |
| `com.google.testing.platform:*` | 0.0.9-alpha04 | Android Software Development Kit License Agreement |
| `javax.annotation:javax.annotation-api` | 1.3.2 | 无上游声明 |

> 这一条是关键：SBOM 的合并清单里同时包含 **LGPL-2.1** 与 **EPL-1.0** 组件，
> 若只看 SBOM 会误判为需要履行 LGPL/EPL 义务。核验后确认二者都只用于 androidTest 工具链。

## 6. 许可证全文

### Apache License 2.0

```
Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

### BSD-2-Clause（以 commonmark 为例，其余 BSD-2 组件同文）

```
Copyright (c) 2015, Atlassian Pty Ltd
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## 7. 维护说明

- 新增或升级依赖后，重新执行第 1 节的两条命令，并据此更新本文件；SBOM 是机器可读的事实来源，本文件是给人看与对外发布的版本。
- 若将来对外发布（应用商店 / 公开分发），需再补：MIT、Bouncy Castle Licence、ML Kit Terms of Service、Android SDK License 的全文（现以第 2 节的官方链接指向）。
