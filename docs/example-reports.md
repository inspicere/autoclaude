# Example Reports

Real output from a homelab infrastructure environment running 10+ projects with ~40k tool calls over 33 days (April-May 2026).

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
  2026-05-01     4,389   3,636      753 ↑    0  82.8%  85.6%     92   1,533   2,763   86
  2026-05-02     3,416   2,927      489 ↓    0  85.7%  85.8%     58   1,434   1,924   16
  2026-05-03     4,407   3,635      771 ↑    1  82.5%  85.6%    118   1,989   2,295  110
  2026-05-04     1,798   1,419      379 ↓    0  78.9%  84.3%     26     850     917   45
  2026-05-05     1,388   1,268      120 ↓    0  91.4%  84.2%     24     695     668    6
  2026-05-06     3,759   3,311      448 ↑    0  88.1%  84.8%     61   1,370   2,313   44
  2026-05-07     2,753   2,230      523 ↑    0  81.0%  84.3%     67   1,324   1,355   13
  2026-05-08     5,724   5,000      724 ↑    0  87.4%  85.0%     19   2,042   3,620   10
  2026-05-09     3,760   3,196      564 ↓    0  85.0%  84.9%     56   1,925   1,756    7
  2026-05-10     3,296   2,857      439 ↓    0  86.7%  85.5%     55   1,549   1,666    3
  ------------ ------- ------- ---------- ---- ------ ------ ------- ------- ------- ----
  TOTAL         39,701  33,661      6,039    1  84.8%      -    631  16,977  21,956  384

  Auto-allow rate: 83.3% (2026-04-08) -> 86.7% (2026-05-10), up 3.3pp
  Prompts: 50 (2026-04-08) -> 439 (2026-05-10), +778%
```

## Summary

```
CLAUDE CODE APPROVAL SUMMARY
  Calls: 39,702 total | 33,662 auto | 6,039 prompted | 1 rejected
  Risk:  631 destructive | 16,978 mutating | 21,956 read-only | 137 unknown
  Secrets: 384 secret-exposure commands approved
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
  SECRET EXPOSURE ANALYSIS - 678 flagged command(s)
==========================================================================================

  By exposure risk:
    EXPOSED  - literal secret in command text (in transcript)      384
    RUNTIME  - secret fetched via $(), may appear in output         30
    VARIABLE - secret referenced via $VAR, may appear in output    173
    PIPE-SAFE - secret flows through pipe, never in transcript      64
    FALSE-POS - not actually a secret (git hash, public key, test data)    27

  By detection category:
    Authorization header                                 301
    High-entropy blob                                    168
    Secret variable assignment                           159
    Known token pattern (ghp_, hvs., sk-, etc.)           36
    JWT token                                             13
    Private key material                                   1
```
