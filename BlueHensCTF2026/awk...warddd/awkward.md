# awk...warddd

## Scenario

We recovered a directory from a misconfigured archive job. Most of the contents appear to be redundant or stale, but a few records still reflect the system’s original processing format. Focus on what remains consistent.

## Given artifact

A directory named 'sorry in advance'

## Solving processs

We are put in around 10000 files with gibberish name, anyway do not expect for some lessons from these competition, no attack chain, no real forensics, just shitty challenges...

Note some file contain a fake flag, but we only pay attention to real files: files with pattern `sys.XXXX.NN.rec`, where NN is its part. Find for them in all sub-folder.

In users:

![](1.png)

In tmp:

![](2.png)

![](3.png)

In logs:

![](4.png)

![](5.png)

In archives:

![](6.png)

![](7.png)

Putting all together:

![](8.png)

`Flag: UDCTF{w3ll_7h47_w45n'7_70_h4rd_w45_17?}`