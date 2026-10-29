# Third-party notices

The BI Agent Harness is licensed under the GPL-3.0-or-later with an attribution term (`NOTICE`). The material
below keeps its own license.

## Microsoft Skills for Fabric

Parts of `.claude/skills/bi-semantic-model/` come from
[microsoft/skills-for-fabric](https://github.com/microsoft/skills-for-fabric), commit
`6c11ad58c25992e5d1435ce7cd80d217d5598a31` (release v0.3.18):

- `references/*.md` except `UPSTREAM.md`: copied unmodified from `skills/semantic-model-authoring/references/`.
- `SKILL.md`: adapted from `skills/semantic-model-authoring/SKILL.md` (workflow selector, tool priority, rules),
  rewritten for PBIP projects with two explicit paths.

The upstream project is licensed under the MIT License:

```text
MIT License

Copyright (c) 2026 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Power BI Desktop base theme

`templates/pbir/Satis_SSAS/Satis_SSAS.Report/StaticResources/SharedResources/BaseThemes/CY26SU09.json` is the base
theme file Power BI Desktop writes into every saved Power BI project. It is Microsoft's, copied unmodified as part of
a saved project; the harness claims no license over it and never edits it.

Microsoft, Power BI and Microsoft Fabric are trademarks of Microsoft Corporation. This project is not affiliated
with or endorsed by Microsoft.
