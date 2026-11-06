package com.docintegrity.forensics

import com.docintegrity.forensics.compare.EntityExtractor
import com.docintegrity.forensics.compare.EntityType
import org.junit.Assert.*
import org.junit.Test
import java.math.BigDecimal

class EntitiesTest {
    private fun ents(vararg lines: String) = EntityExtractor.extract(lines.toList())
    private fun keys(t: EntityType, vararg lines: String) = ents(*lines).filter { it.type == t }.map { it.key }

    @Test fun datesInManyFormatsNormaliseToIso() {
        assertEquals(listOf("2024-03-12"), keys(EntityType.DATE, "Date of issue: 12 March 2024"))
        assertEquals(listOf("2024-03-12"), keys(EntityType.DATE, "Issued March 12, 2024"))
        assertEquals(listOf("2024-03-12"), keys(EntityType.DATE, "Date 2024-03-12"))
        assertEquals(listOf("2024-03-12"), keys(EntityType.DATE, "12th Mar 2024"))
        assertEquals(listOf("2024-12-25"), keys(EntityType.DATE, "25/12/2024"))
        assertEquals(listOf("2024-12-25"), keys(EntityType.DATE, "12/25/2024"))   // only month-first is valid
    }

    @Test fun ambiguousNumericDatesKeepBothReadings() {
        val e = ents("Date: 03/04/2024").single { it.type == EntityType.DATE }
        assertEquals(setOf("2024-04-03", "2024-03-04"), e.altKeys)
        val a = ents("03/04/2024").single(); val b = ents("4 March 2024").single()
        assertTrue("ambiguous 03/04/2024 may equal 4 March", a.matches(b))
        assertFalse(a.matches(ents("5 March 2024").single()))
    }

    @Test fun amountsNormaliseSeparatorsAndCurrency() {
        assertEquals(listOf("ZMW|4250"), keys(EntityType.AMOUNT, "Total received ZMW 4,250.00"))
        assertEquals(listOf("\$|1250"), keys(EntityType.AMOUNT, "Fee: \$1,250"))
        assertEquals(listOf("EUR|4250.5"), keys(EntityType.AMOUNT, "Betrag EUR 4.250,50"))
        assertEquals(listOf("|12.5"), keys(EntityType.AMOUNT, "Rate 12.50"))
        assertEquals(listOf("|4250"), keys(EntityType.AMOUNT, "Total 4250"))   // amount-like label
    }

    @Test fun plainNumbersAreNotAmounts() {
        assertTrue(keys(EntityType.AMOUNT, "Qty 1", "Page 2 of 3", "Year 2024", "Room 12").isEmpty())
    }

    @Test fun amountsWithAndWithoutCurrencyStillMatch() {
        val a = ents("Total ZMW 4,250.00").single { it.type == EntityType.AMOUNT }
        val b = ents("Total 4,250.00").single { it.type == EntityType.AMOUNT }
        assertTrue(a.matches(b))
        assertFalse(a.matches(ents("Total ZMW 42,500.00").single { it.type == EntityType.AMOUNT }))
        assertFalse("different currencies never match", ents("Total USD 100.00").single { it.type == EntityType.AMOUNT }.matches(ents("Total EUR 100.00").single { it.type == EntityType.AMOUNT }))
    }

    @Test fun documentNumbersLabelledAndPatterned() {
        assertEquals(listOf("RC2024004217"), keys(EntityType.DOC_NUMBER, "Receipt No: RC-2024-004217"))
        assertTrue(keys(EntityType.DOC_NUMBER, "Payment reference: INV-77831").contains("INV77831"))
        assertEquals(listOf("A1234567"), keys(EntityType.DOC_NUMBER, "Passport No. A1234567"))
        assertTrue(keys(EntityType.DOC_NUMBER, "Total 4,250.00").isEmpty())
    }

    @Test fun namesOnlyAfterLabelsAndStopAtNextField() {
        assertEquals(listOf("john mwansa"), keys(EntityType.NAME, "Received from: John Mwansa"))
        assertEquals(listOf("grace banda"), keys(EntityType.NAME, "Received by: Grace Banda, Finance Officer"))
        assertEquals(listOf("john mwansa"), keys(EntityType.NAME, "Name: John Mwansa Date: 12 March 2024"))
        assertEquals(listOf("anna k. lee"), keys(EntityType.NAME, "Issued to: Dr. Anna K. Lee"))
        assertTrue("capitalised words without a label are not names", keys(EntityType.NAME, "Finance Office Zambia").isEmpty())
    }

    @Test fun nameWrappedOntoNextLineIsRejoined() {
        assertEquals(listOf("joseph mwanza"), keys(EntityType.NAME, "Received from: Joseph", "Mwanza", "Payment reference: INV-1"))
        // but a following label line is never swallowed
        assertEquals(listOf("joseph"), keys(EntityType.NAME, "Received from: Joseph", "Date: 12 March 2024"))
    }

    @Test fun numberParsingCases() {
        assertEquals(BigDecimal("1250"), EntityExtractor.parseNumber("1,250"))
        assertEquals(BigDecimal("1250"), EntityExtractor.parseNumber("1.250"))
        assertEquals(BigDecimal("1250.50"), EntityExtractor.parseNumber("1,250.50"))
        assertEquals(BigDecimal("1250.50"), EntityExtractor.parseNumber("1.250,50"))
        assertEquals(BigDecimal("12.5"), EntityExtractor.parseNumber("12,5"))
        assertEquals(BigDecimal("1234567"), EntityExtractor.parseNumber("1 234 567"))
    }
}
