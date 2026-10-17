# AIRCHAT: keep mesh/crypto/storage classes intact under minification.
-keep class com.airchat.mesh.** { *; }
-keepclassmembers class com.airchat.mesh.** { *; }
# Tink subtle primitives are referenced reflectively-free; keep the subtle package.
-keep class com.google.crypto.tink.subtle.** { *; }
