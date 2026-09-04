# ML Kit barcode scanning discovers these registrars and implementation
# classes through reflection.  R8 otherwise removes them from release APKs,
# which makes BarcodeScanning.getClient() fail with a null-object NPE.
-keep class com.google.mlkit.** { *; }
# The bundled barcode model (the default mobile_scanner backend) keeps its
# implementation in a package that is not covered by com.google.mlkit.**.
# R8 full mode can otherwise remove a factory/registrar and ML Kit fails at
# startup with the opaque Android null-object getClass() exception.
-keep class com.google.android.gms.internal.mlkit_vision_barcode_bundled.** { *; }
-keep class com.google.android.gms.internal.mlkit_vision_barcode.** { *; }
-keep class com.google.android.gms.internal.mlkit_vision_common.** { *; }
# Bundled barcode builds use a third internal namespace. Keep it as well so
# a future ML Kit split/rename cannot remove a reflection-loaded registrar.
-keep class com.google.android.gms.internal.mlkit_** { *; }
-keep class com.google.android.libraries.barhopper.** { *; }
-keep class com.google.photos.** { *; }
-keep class com.google.photos.vision.barhopper.** { *; }

# ML Kit uses generated enum/protobuf members reflectively.
-keepclassmembers class * extends java.lang.Enum {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
