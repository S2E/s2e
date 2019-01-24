# Copyright (c) 2019 Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This R script plots the overhead of binaries produced by Revgen.
# The plot is a horizontal bar chart. The Y axis is the name of the binary,
# the X axis is the size (in log scale).
#
# The input data (*.stats file) can be generated with the revgen-gen-stats.sh script.
#
# Modify the two variables below according to your needs.
INPUT_STATS_FILE <- "revgen-overhead.stats"
OUTPUT_SVG_FILE <- "revgen-overhead.svg"

#####################################################################
print_data_stats <- function(data) {
  cat("Overhead stats\n")
  cat("Median: ", median(data$Overhead, na.rm = TRUE), "\n")
  cat("Mean: ", mean(data$Overhead, na.rm = TRUE), "\n")
  cat("Min: ", min(data$Overhead, na.rm = TRUE), "\n")
  cat("Max: ", max(data$Overhead, na.rm = TRUE), "\n")
}

plot_size_overhead <- function(data) {
  colors <- c("black","grey")
  
  # Adjust plotting params (mar=margin size)
  par(mar=c(7,9,2, 3), mai=c(1,2,1,1))
  
  barplot(
    rbind(data$InputBinSize / 1024, data$RevgenBinSize / 1024), 
    horiz=TRUE, 
    names.arg = data$BinaryName, 
    las=1, 
    xlab = "Binary size (KB)",
    xlim = c(1, 10000),
    log = "x",
    col=colors,
    yaxs = "i" # This removes the 4% margin around the plot
  )
  
  legend_labels <- c(
    "Input binary", 
    "Output binary"
  )
  
  title("Binary Sizes (KB)", line=3)
  legend("topright", legend_labels, fill = colors)
  grid()
  axis(side = 3)
}

data <- read.delim(INPUT_STATS_FILE, na.strings = "N/A")

# Clear broken data
data[is.na(data$RevgenBinSize),]$InputBinSize <- 1024

# Compute overhead
data['Overhead'] <- data$RevgenBinSize / data$InputBinSize

# na <- na.omit(data)
old.par <- par(mar = c(0, 0, 0, 0))

svg(OUTPUT_SVG_FILE, width = 10, height=60 )

plot_size_overhead(data)

dev.off()

print_data_stats(data)