# Example Reports

Real output from a homelab infrastructure environment running 10+ projects with ~39k tool calls over 33 days (April-May 2026).

## Trend

```
CLAUDE CODE TREND ANALYSIS (by day)
========================================================================================
  Day            Total    Auto   Prompted  Rej  Auto%   Avg7  Destr   Mutat     R/O  Sec
  ------------ ------- ------- ---------- ---- ------ ------ ------- ------- ------- ----
  2026-04-08       300     250         50    0  83.3%  83.3%      0     196      96    0
  2026-04-09        57      36       21 ↓    0  63.2%  73.2%      0      34      23    0
  2026-04-10        32      22       10 ↓    0  68.8%  71.7%      1      21      10    1
  2026-04-13        27      19        8 ↓    0  70.4%  71.4%      0      20       7    0
  2026-04-14         7       6        1 ↓    0  85.7%  74.3%      0       2       5    0
  2026-04-15       283     212       71 ↑    0  74.9%  74.4%     10     189      84   10
  2026-04-16       103      90       13 ↓    0  87.4%  76.2%      7      73      23    7
  2026-04-25     1,161     972      189 ↑    0  83.7%  76.3%      4     568     589    3
  2026-04-26       126     106       20 ↓    0  84.1%  79.3%      0      75      51    0
  2026-04-27       238     209       29 ↑    0  87.8%  82.0%      0     118     120    0
  2026-04-28       106      98        8 ↓    0  92.5%  85.2%      0      48      58    0
  2026-04-29       980     819      161 ↑    0  83.6%  84.9%     12     497     468    5
  2026-04-30     1,591   1,343      248 ↑    0  84.4%  86.2%     21     425   1,145   18
  2026-05-01     4,389   3,636      753 ↑    0  82.8%  85.6%     92   1,533   2,763   87
  2026-05-02     3,416   2,927      489 ↓    0  85.7%  85.8%     58   1,434   1,924   17
  2026-05-03     4,407   3,635      771 ↑    1  82.5%  85.6%    118   1,989   2,295  113
  2026-05-04     1,798   1,419      379 ↓    0  78.9%  84.3%     26     850     917   45
  2026-05-05     1,388   1,268      120 ↓    0  91.4%  84.2%     24     695     668    6
  2026-05-06     3,759   3,308      451 ↑    0  88.0%  84.8%     61   1,370   2,313   48
  2026-05-07     2,753   2,214      539 ↑    0  80.4%  84.2%     67   1,324   1,355   21
  2026-05-08     5,724   4,991      733 ↑    0  87.2%  84.9%     19   2,042   3,620   10
  2026-05-09     3,760   3,193      567 ↓    0  84.9%  84.8%     56   1,925   1,756    8
  2026-05-10     2,485   2,139      346 ↓    0  86.1%  85.3%     39   1,155   1,265   11
  ------------ ------- ------- ---------- ---- ------ ------ ------- ------- ------- ----
  TOTAL         38,890  32,912      5,977    1  84.6%      -    615  16,583  21,555  410

  Auto-allow rate: 83.3% (2026-04-08) -> 86.1% (2026-05-10), up 2.7pp
  Prompts: 50 (2026-04-08) -> 346 (2026-05-10), +592%
```

## Summary

```
CLAUDE CODE APPROVAL SUMMARY
  Calls: 38,891 total | 32,913 auto | 5,977 prompted | 1 rejected
  Risk:  615 destructive | 16,584 mutating | 21,555 read-only | 137 unknown
  Secrets: 410 secret-exposure commands approved
  WARNING: These secrets are already written to disk in session JSONL files
  (~/.claude/projects/) and were sent to the Claude API. They should be
  rotated and considered compromised.

  Top prompted:
    1. Bash: ssh                                (160x)
    2. Bash: python3                            (143x)
    3. Bash: (comment/shebang) [secrets]        (116x)
    4. Bash: sudo                               (89x)
    5. Bash: wc                                 (84x)

  Top suggestions:
    1. Bash(ssh *)                              (107 approvals, mutating)
    2. Bash(wc *)                               (83 approvals, read-only)
    3. Bash(python3 *)                          (75 approvals, mutating)
```

## Secret exposure analysis

```
==========================================================================================
  SECRET EXPOSURE ANALYSIS - 663 flagged command(s)
==========================================================================================

  By exposure risk:
    EXPOSED  - literal secret in command text (in transcript)      410
    RUNTIME  - secret fetched via $(), may appear in output         30
    VARIABLE - secret referenced via $VAR, may appear in output    161
    PIPE-SAFE - secret flows through pipe, never in transcript      62

  By detection category:
    Authorization header                                 287
    High-entropy blob                                    167
    Secret variable assignment                           159
    Known token pattern (ghp_, hvs., sk-, etc.)           36
    JWT token                                             13
    Private key material                                   1
```
