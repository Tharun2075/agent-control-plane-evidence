# Batch 17 p3 summary (protocol: repeats/batch17/PROTOCOL.md; recompute: tools/batch17_summary.py --check)

## deepseek.v3.2 / gated
- runs 100 of 100 planned (attacked 40, benign 60); errors 0; dirty 0
- ASR 1/40 = 0.025 [0.004, 0.129]
- utility benign 46/60 = 0.767 [0.646, 0.856]
- utility attacked 21/40 = 0.525 [0.375, 0.671]
- calls: converse 699, reviewer 0; tokens in 4366103 out 105390; cost USD 2.9020 (reviewer 0.0000) at list price; wall 1521 s

## deepseek.v3.2 / plain
- runs 100 of 100 planned (attacked 40, benign 60); errors 0; dirty 0
- ASR 26/40 = 0.650 [0.495, 0.779]
- utility benign 50/60 = 0.833 [0.720, 0.907]
- utility attacked 12/40 = 0.300 [0.181, 0.454]
- calls: converse 583, reviewer 0; tokens in 3245074 out 84529; cost USD 2.1683 (reviewer 0.0000) at list price; wall 1375 s

## openai.gpt-oss-120b-1:0 / gated
- runs 100 of 100 planned (attacked 40, benign 60); errors 0; dirty 0
- ASR 2/40 = 0.050 [0.014, 0.165]
- utility benign 34/60 = 0.567 [0.441, 0.684]
- utility attacked 12/40 = 0.300 [0.181, 0.454]
- calls: converse 564, reviewer 0; tokens in 2002571 out 156969; cost USD 0.3946 (reviewer 0.0000) at list price; wall 960 s

## openai.gpt-oss-120b-1:0 / plain
- runs 100 of 100 planned (attacked 40, benign 60); errors 0; dirty 0
- ASR 15/40 = 0.375 [0.242, 0.530]
- utility benign 39/60 = 0.650 [0.524, 0.758]
- utility attacked 14/40 = 0.350 [0.221, 0.505]
- calls: converse 629, reviewer 0; tokens in 2545324 out 164086; cost USD 0.4802 (reviewer 0.0000) at list price; wall 991 s
