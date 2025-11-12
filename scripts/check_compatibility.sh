#!/bin/bash
# Android 12-14 Compatibility Checker Script
# This script validates that the codebase follows Android 12-14 best practices

set -e

echo "=========================================="
echo "Android 12-14 Compatibility Checker"
echo "=========================================="
echo ""

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

ERRORS=0
WARNINGS=0

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Helper functions
error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ERRORS=$((ERRORS + 1))
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

info() {
    echo "[INFO] $1"
}

echo "Checking project structure..."
if [ ! -f "app/build.gradle" ]; then
    error "app/build.gradle not found"
    exit 1
fi
success "Project structure valid"
echo ""

# Check 1: Target SDK version
echo "1. Checking SDK versions..."
TARGET_SDK=$(grep -m 1 "targetSdkVersion" app/build.gradle | grep -oP '\d+' || echo "0")
MIN_SDK=$(grep -m 1 "minSdkVersion" app/build.gradle | grep -oP '\d+' || echo "0")
COMPILE_SDK=$(grep -m 1 "compileSdkVersion" app/build.gradle | grep -oP '\d+' || echo "0")

info "Min SDK: $MIN_SDK"
info "Target SDK: $TARGET_SDK"
info "Compile SDK: $COMPILE_SDK"

if [ "$TARGET_SDK" -lt 33 ]; then
    error "Target SDK is $TARGET_SDK, should be 33+ for Android 13 compatibility"
else
    success "Target SDK is $TARGET_SDK (Android 13+)"
fi

if [ "$MIN_SDK" -lt 23 ]; then
    warning "Min SDK is $MIN_SDK, recommended 23+ for modern permission model"
else
    success "Min SDK is $MIN_SDK (Android 6.0+)"
fi
echo ""

# Check 2: PendingIntent flags
echo "2. Checking PendingIntent flags (Android 12+)..."
PENDING_INTENTS=$(grep -rn "PendingIntent\." app/src/main/java/ --include="*.java" | grep -v "import" || echo "")

if [ -z "$PENDING_INTENTS" ]; then
    warning "No PendingIntent usage found"
else
    # Check for FLAG_MUTABLE or FLAG_IMMUTABLE
    if grep -rq "FLAG_MUTABLE\|FLAG_IMMUTABLE" app/src/main/java/ --include="*.java"; then
        success "PendingIntent flags (FLAG_MUTABLE/FLAG_IMMUTABLE) found"
        
        # Check specific instances
        MUTABLE_COUNT=$(grep -r "FLAG_MUTABLE" app/src/main/java/ --include="*.java" | wc -l)
        IMMUTABLE_COUNT=$(grep -r "FLAG_IMMUTABLE" app/src/main/java/ --include="*.java" | wc -l)
        info "  - FLAG_MUTABLE: $MUTABLE_COUNT occurrences"
        info "  - FLAG_IMMUTABLE: $IMMUTABLE_COUNT occurrences"
    else
        error "PendingIntent flags missing (required for Android 12+)"
    fi
fi
echo ""

# Check 3: Exported components in manifest
echo "3. Checking exported components (Android 12+)..."
MANIFEST="app/src/main/AndroidManifest.xml"

if [ ! -f "$MANIFEST" ]; then
    error "AndroidManifest.xml not found"
else
    # Check activities with intent-filters
    ACTIVITIES_WITH_FILTERS=$(grep -c "intent-filter" "$MANIFEST" | grep -A10 "activity" || echo "0")
    EXPORTED_ACTIVITIES=$(grep -c 'android:exported="true"' "$MANIFEST" || echo "0")
    
    if [ "$EXPORTED_ACTIVITIES" -gt 0 ]; then
        success "Exported activities properly declared"
        info "  - Activities with android:exported: $EXPORTED_ACTIVITIES"
    else
        warning "No exported activities found (may be issue if app has launcher activity)"
    fi
    
    # Check receivers with intent-filters
    if grep -q "<receiver" "$MANIFEST"; then
        if grep -A5 "<receiver" "$MANIFEST" | grep -q "android:exported"; then
            success "Broadcast receivers properly declared with android:exported"
        else
            warning "Some receivers may be missing android:exported attribute"
        fi
    fi
fi
echo ""

# Check 4: POST_NOTIFICATIONS permission (Android 13+)
echo "4. Checking POST_NOTIFICATIONS permission (Android 13+)..."
if grep -q "android.permission.POST_NOTIFICATIONS" "$MANIFEST"; then
    success "POST_NOTIFICATIONS permission declared in manifest"
    
    # Check if it's requested in code
    if grep -rq "POST_NOTIFICATIONS" app/src/main/java/ --include="*.java"; then
        success "POST_NOTIFICATIONS permission checked in code"
    else
        warning "POST_NOTIFICATIONS declared but not checked in code"
    fi
else
    error "POST_NOTIFICATIONS permission missing (required for Android 13+)"
fi
echo ""

# Check 5: Notification channels (Android 8+)
echo "5. Checking Notification Channels (Android 8+)..."
if grep -rq "NotificationChannel" app/src/main/java/ --include="*.java"; then
    success "NotificationChannel usage found"
    
    if grep -rq "Build.VERSION.SDK_INT.*O\|Build.VERSION_CODES.O" app/src/main/java/ --include="*.java"; then
        success "Notification channels properly version-gated"
    else
        warning "NotificationChannel found but version check unclear"
    fi
else
    warning "No NotificationChannel found (required for Android 8+)"
fi
echo ""

# Check 6: SMS permissions
echo "6. Checking SMS permissions..."
SMS_PERMS=("SEND_SMS" "RECEIVE_SMS" "READ_SMS")
for perm in "${SMS_PERMS[@]}"; do
    if grep -q "android.permission.$perm" "$MANIFEST"; then
        success "$perm permission declared"
    else
        warning "$perm permission not declared (may not be needed)"
    fi
done
echo ""

# Check 7: Runtime permission requests
echo "7. Checking runtime permission handling..."
if grep -rq "requestPermissions\|checkSelfPermission" app/src/main/java/ --include="*.java"; then
    success "Runtime permission handling found"
    
    # Check for permission rationale
    if grep -rq "shouldShowRequestPermissionRationale" app/src/main/java/ --include="*.java"; then
        success "Permission rationale handling found"
    else
        info "Permission rationale not found (optional but recommended)"
    fi
else
    warning "No runtime permission handling found"
fi
echo ""

# Check 8: Deprecated API usage
echo "8. Checking for deprecated APIs..."
DEPRECATED_APIS=(
    "getColor.*getResources" 
    "getDrawable.*getResources"
    "PhoneNumberUtils.formatNumber.*[^,]$"
)

DEPRECATED_FOUND=0
for api in "${DEPRECATED_APIS[@]}"; do
    if grep -rqE "$api" app/src/main/java/ --include="*.java"; then
        warning "Potentially deprecated API pattern found: $api"
        DEPRECATED_FOUND=1
    fi
done

if [ $DEPRECATED_FOUND -eq 0 ]; then
    success "No obvious deprecated APIs found"
fi
echo ""

# Check 9: Documentation
echo "9. Checking documentation..."
if [ -f "ANDROID_COMPATIBILITY.md" ]; then
    success "ANDROID_COMPATIBILITY.md exists"
else
    warning "ANDROID_COMPATIBILITY.md not found"
fi

if [ -f "TESTING_GUIDE.md" ]; then
    success "TESTING_GUIDE.md exists"
else
    warning "TESTING_GUIDE.md not found"
fi
echo ""

# Check 10: Gradle configuration
echo "10. Checking Gradle configuration..."
if grep -q "androidx.appcompat:appcompat" app/build.gradle; then
    success "AndroidX libraries in use"
else
    warning "AndroidX libraries not found, may be using legacy support libs"
fi

if grep -q "sourceCompatibility.*11\|targetCompatibility.*11" app/build.gradle; then
    success "Java 11 configured"
else
    warning "Java version configuration unclear"
fi
echo ""

# Summary
echo "=========================================="
echo "Compatibility Check Summary"
echo "=========================================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo "The app appears to be fully compatible with Android 12-14."
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Checks completed with $WARNINGS warning(s)${NC}"
    echo "The app should work but review warnings above."
else
    echo -e "${RED}✗ Checks completed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo "Please fix the errors above for full Android 12-14 compatibility."
fi
echo ""

exit $ERRORS
