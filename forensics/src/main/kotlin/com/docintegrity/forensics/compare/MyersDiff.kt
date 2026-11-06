package com.docintegrity.forensics.compare

/** Edit script element over two token sequences. */
sealed class Edit {
    /** Tokens [aFrom, aTo) of A correspond to [bFrom, bTo) of B and are equal. */
    class Equal(val aFrom: Int, val aTo: Int, val bFrom: Int, val bTo: Int) : Edit()
    /** Tokens [aFrom, aTo) of A were replaced by [bFrom, bTo) of B (either side may be empty). */
    class Change(val aFrom: Int, val aTo: Int, val bFrom: Int, val bTo: Int) : Edit()
}

/**
 * Myers O(ND) shortest-edit-script diff. [maxD] bounds the work for pathological inputs; if exceeded the whole
 * range is returned as a single Change (the caller reports that detail was truncated).
 */
object MyersDiff {
    class Result(val edits: List<Edit>, val truncated: Boolean)

    fun diff(a: List<String>, b: List<String>, maxD: Int = 1500): Result {
        // trim common prefix/suffix
        var pre = 0
        while (pre < a.size && pre < b.size && a[pre] == b[pre]) pre++
        var suf = 0
        while (suf < a.size - pre && suf < b.size - pre && a[a.size - 1 - suf] == b[b.size - 1 - suf]) suf++
        val a2 = a.subList(pre, a.size - suf); val b2 = b.subList(pre, b.size - suf)
        val edits = ArrayList<Edit>()
        if (pre > 0) edits.add(Edit.Equal(0, pre, 0, pre))
        var truncated = false
        if (a2.isEmpty() && b2.isEmpty()) {
            // identical
        } else if (a2.isEmpty() || b2.isEmpty()) {
            edits.add(Edit.Change(pre, pre + a2.size, pre, pre + b2.size))
        } else {
            val ops = myers(a2, b2, maxD)
            if (ops == null) {
                truncated = true
                edits.add(Edit.Change(pre, pre + a2.size, pre, pre + b2.size))
            } else {
                // ops: list of (type, ...) -> build edits, offsetting by pre
                var ai = 0; var bi = 0
                var i = 0
                while (i < ops.size) {
                    if (ops[i] == 0) { // match
                        val sa = ai; val sb = bi
                        while (i < ops.size && ops[i] == 0) { ai++; bi++; i++ }
                        edits.add(Edit.Equal(pre + sa, pre + ai, pre + sb, pre + bi))
                    } else {
                        val sa = ai; val sb = bi
                        while (i < ops.size && ops[i] != 0) { if (ops[i] == 1) ai++ else bi++; i++ }
                        edits.add(Edit.Change(pre + sa, pre + ai, pre + sb, pre + bi))
                    }
                }
            }
        }
        if (suf > 0) edits.add(Edit.Equal(a.size - suf, a.size, b.size - suf, b.size))
        return Result(edits, truncated)
    }

    /** Returns ops: 0 = match, 1 = delete from A, 2 = insert from B; null when D exceeds [maxD]. */
    private fun myers(a: List<String>, b: List<String>, maxD: Int): IntArray? {
        val n = a.size; val m = b.size
        val max = minOf(n + m, maxD)
        val offset = max + 1
        var v = IntArray(2 * max + 3)
        val trace = ArrayList<IntArray>()
        var found = -1
        loop@ for (d in 0..max) {
            trace.add(v.copyOf())
            for (k in -d..d step 2) {
                var x = if (k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1])) v[offset + k + 1] else v[offset + k - 1] + 1
                var y = x - k
                while (x < n && y < m && a[x] == b[y]) { x++; y++ }
                v[offset + k] = x
                if (x >= n && y >= m) { found = d; break@loop }
            }
        }
        if (found < 0) return null
        // backtrack
        val ops = ArrayList<Int>()
        var x = n; var y = m
        for (d in found downTo 1) {
            val vv = trace[d]
            val k = x - y
            val prevK = if (k == -d || (k != d && vv[offset + k - 1] < vv[offset + k + 1])) k + 1 else k - 1
            val prevX = vv[offset + prevK]; val prevY = prevX - prevK
            while (x > prevX && y > prevY) { ops.add(0); x--; y-- }
            if (x == prevX) ops.add(2) else ops.add(1)
            x = prevX; y = prevY
        }
        while (x > 0 && y > 0) { ops.add(0); x--; y-- }
        ops.reverse()
        return ops.toIntArray()
    }
}
