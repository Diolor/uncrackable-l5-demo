# Strip all android.util.Log calls from the release build (no logging in any build type).
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
    public static *** println(...);
}
# Obfuscation stays light: L5 is a protocol challenge, not an obfuscation one.
-keepattributes *Annotation*
-dontwarn org.bouncycastle.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
# OkHttp JVM's optional build-time API compatibility annotation has no runtime behavior.
-dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement
