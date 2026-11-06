# PdfBox-Android and BouncyCastle use reflection / optional classes.
-keep class com.tom_roush.** { *; }
-dontwarn com.tom_roush.**
-dontwarn org.bouncycastle.**
-dontwarn javax.**
-dontwarn java.awt.**
-dontwarn org.apache.**
-dontwarn com.gemalto.jp2.**
