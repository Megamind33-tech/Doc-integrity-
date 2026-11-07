# PdfBox-Android and BouncyCastle use reflection / optional classes.
-keep class com.tom_roush.** { *; }
-dontwarn com.tom_roush.**
-dontwarn org.bouncycastle.**
-dontwarn javax.**
-dontwarn java.awt.**
-dontwarn org.apache.**
-dontwarn com.gemalto.jp2.**

# BouncyCastle registers its algorithms by class NAME (Class.forName in BouncyCastleProvider); R8 cannot see those
# references, so keep the provider tree or signature verification would fail only in the minified build.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-keep class org.bouncycastle.cms.** { *; }
-keep class org.bouncycastle.cert.** { *; }
-keep class org.bouncycastle.tsp.** { *; }
-keep class org.bouncycastle.asn1.** { *; }
# PdfBox-Android loads fonts/CMaps/glyph lists via reflection and assets.
-keep class com.docintegrity.forensics.** { *; }
