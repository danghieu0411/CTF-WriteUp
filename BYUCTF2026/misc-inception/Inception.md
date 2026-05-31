# Inception

## Scenario

I found this weird file on my computer. I tried opening it, but there were some problems.

## Solve

The given file is merged from 3 distinct files, `binwalk` may not work as expected, use `foremost` instead

First is a png image holding the first chunk:

![](1.png)

Second is a text file inside a zip file:

![](2.png)

Finally, the PDF:

![](3.png)

`Flag: byuctf{wh4t_th3_fr3ak}`