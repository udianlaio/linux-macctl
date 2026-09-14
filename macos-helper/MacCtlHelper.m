#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <Vision/Vision.h>
#import <ServiceManagement/ServiceManagement.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>

static NSString *gOutputPath = nil;

static void emit(NSDictionary *d) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    puts(s.UTF8String);
    if (gOutputPath.length > 0) {
        NSString *line = [s stringByAppendingString:@"\n"];
        [line writeToFile:gOutputPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

static NSString *smAppServiceStatusName(SMAppServiceStatus status) {
    switch (status) {
        case SMAppServiceStatusNotRegistered: return @"NOT_REGISTERED";
        case SMAppServiceStatusEnabled: return @"ENABLED";
        case SMAppServiceStatusRequiresApproval: return @"REQUIRES_APPROVAL";
        case SMAppServiceStatusNotFound: return @"NOT_FOUND";
    }
    return @"UNKNOWN";
}

static NSString *loginReadyMarkerPath(void) {
    NSString *base = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/MacCtl"];
    return [base stringByAppendingPathComponent:@"login-ready.json"];
}

static BOOL writeJSONDictionary(NSDictionary *payload, NSString *path, NSError **error) {
    NSString *dir = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:error]) {
        return NO;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:error];
    if (!data) return NO;
    NSMutableData *line = [data mutableCopy];
    const char newline = '\n';
    [line appendBytes:&newline length:1];
    return [line writeToFile:path options:NSDataWritingAtomic error:error];
}

static NSDictionary *readJSONDictionary(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

static NSDictionary *lifecycleStatePayload(void) {
    SMAppService *service = [SMAppService mainAppService];
    NSString *markerPath = loginReadyMarkerPath();
    NSDictionary *marker = readJSONDictionary(markerPath);
    return @{
        @"service": @"SMAppService.mainAppService",
        @"service_status": smAppServiceStatusName(service.status),
        @"service_status_raw": @(service.status),
        @"marker_path": markerPath,
        @"marker_present": @(marker != nil),
        @"marker": marker ?: [NSNull null],
        @"accessibility": @(AXIsProcessTrusted()),
        @"screen_recording": @(CGPreflightScreenCaptureAccess()),
        @"bundle": NSBundle.mainBundle.bundleIdentifier ?: @"unknown"
    };
}

static int lifecycleRegister(void) {
    SMAppService *service = [SMAppService mainAppService];
    NSError *error = nil;
    BOOL ok = [service registerAndReturnError:&error];
    NSMutableDictionary *payload = [lifecycleStatePayload() mutableCopy];
    payload[@"status"] = ok ? @"PASS" : @"FAIL";
    payload[@"operation"] = @"lifecycle_register";
    if (error) payload[@"error"] = error.localizedDescription ?: @"unknown";
    emit(payload);
    return ok ? 0 : 1;
}

static int lifecycleUnregister(void) {
    SMAppService *service = [SMAppService mainAppService];
    NSError *error = nil;
    BOOL ok = [service unregisterAndReturnError:&error];
    NSMutableDictionary *payload = [lifecycleStatePayload() mutableCopy];
    payload[@"status"] = ok ? @"PASS" : @"FAIL";
    payload[@"operation"] = @"lifecycle_unregister";
    if (error) payload[@"error"] = error.localizedDescription ?: @"unknown";
    emit(payload);
    return ok ? 0 : 1;
}

static int loginBootstrap(void) {
    SMAppService *service = [SMAppService mainAppService];
    NSISO8601DateFormatter *fmt = [[NSISO8601DateFormatter alloc] init];
    NSDictionary *payload = @{
        @"status": @"PASS",
        @"event": @"login_bootstrap",
        @"timestamp": [fmt stringFromDate:[NSDate date]],
        @"user": NSUserName() ?: @"unknown",
        @"pid": @([[NSProcessInfo processInfo] processIdentifier]),
        @"bundle": NSBundle.mainBundle.bundleIdentifier ?: @"unknown",
        @"service_status": smAppServiceStatusName(service.status),
        @"accessibility": @(AXIsProcessTrusted()),
        @"screen_recording": @(CGPreflightScreenCaptureAccess())
    };
    NSError *error = nil;
    NSString *marker = loginReadyMarkerPath();
    BOOL wrote = writeJSONDictionary(payload, marker, &error);
    NSMutableDictionary *out = [payload mutableCopy];
    out[@"marker_path"] = marker;
    out[@"marker_written"] = @(wrote);
    if (error) out[@"marker_error"] = error.localizedDescription ?: @"unknown";
    emit(out);
    return wrote ? 0 : 1;
}

static NSRunningApplication *runningApp(NSString *bundleID) {
    return [[NSRunningApplication runningApplicationsWithBundleIdentifier:bundleID] firstObject];
}

static int accessibilityTest(void) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    NSRunningApplication *finder = runningApp(@"com.apple.finder");
    if (!finder) {
        emit(@{@"status":@"FAIL", @"accessibility":@YES, @"reason":@"finder_not_running"});
        return 1;
    }
    AXUIElementRef app = AXUIElementCreateApplication(finder.processIdentifier);
    CFTypeRef windows = NULL;
    AXError rc = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windows);
    NSInteger count = 0;
    if (rc == kAXErrorSuccess && windows && CFGetTypeID(windows) == CFArrayGetTypeID()) {
        count = CFArrayGetCount((CFArrayRef)windows);
    }
    if (windows) CFRelease(windows);
    CFRelease(app);
    emit(@{@"status": rc == kAXErrorSuccess ? @"PASS" : @"FAIL",
           @"accessibility":@YES,
           @"target":@"Finder",
           @"finder_pid":@(finder.processIdentifier),
           @"window_count":@(count),
           @"ax_error":@(rc)});
    return rc == kAXErrorSuccess ? 0 : 1;
}

static int accessibilityActionTest(void) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    NSRunningApplication *finder = runningApp(@"com.apple.finder");
    if (!finder) {
        emit(@{@"status":@"FAIL", @"reason":@"finder_not_running"});
        return 1;
    }
    AXUIElementRef app = AXUIElementCreateApplication(finder.processIdentifier);
    CFTypeRef windows = NULL;
    AXError rc = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windows);
    if (rc != kAXErrorSuccess || !windows || CFGetTypeID(windows) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)windows) == 0) {
        if (windows) CFRelease(windows);
        CFRelease(app);
        emit(@{@"status":@"FAIL", @"operation":@"finder_window", @"ax_error":@(rc)});
        return 1;
    }

    AXError action = kAXErrorActionUnsupported;
    NSString *actionName = @"none";
    NSString *title = @"";
    CFIndex selected = -1;
    CFIndex count = CFArrayGetCount((CFArrayRef)windows);
    for (CFIndex i = 0; i < count; i++) {
        AXUIElementRef win = (AXUIElementRef)CFArrayGetValueAtIndex((CFArrayRef)windows, i);
        CFTypeRef titleRef = NULL;
        AXUIElementCopyAttributeValue(win, kAXTitleAttribute, &titleRef);
        if (titleRef && CFGetTypeID(titleRef) == CFStringGetTypeID()) title = [(__bridge NSString *)titleRef copy];
        if (titleRef) CFRelease(titleRef);

        CFArrayRef actions = NULL;
        AXError arc = AXUIElementCopyActionNames(win, &actions);
        BOOL supportsRaise = (arc == kAXErrorSuccess && actions && CFArrayContainsValue(actions, CFRangeMake(0, CFArrayGetCount(actions)), kAXRaiseAction));
        if (actions) CFRelease(actions);
        if (supportsRaise) {
            action = AXUIElementPerformAction(win, kAXRaiseAction);
            actionName = @"AXRaise";
            selected = i;
            if (action == kAXErrorSuccess) break;
        }

        Boolean settable = false;
        if (AXUIElementIsAttributeSettable(win, kAXMainAttribute, &settable) == kAXErrorSuccess && settable) {
            action = AXUIElementSetAttributeValue(win, kAXMainAttribute, kCFBooleanTrue);
            actionName = @"SetAXMain";
            selected = i;
            if (action == kAXErrorSuccess) break;
        }
        settable = false;
        if (AXUIElementIsAttributeSettable(win, kAXFocusedAttribute, &settable) == kAXErrorSuccess && settable) {
            action = AXUIElementSetAttributeValue(win, kAXFocusedAttribute, kCFBooleanTrue);
            actionName = @"SetAXFocused";
            selected = i;
            if (action == kAXErrorSuccess) break;
        }
    }

    BOOL unsupported = (action == kAXErrorActionUnsupported && selected < 0);
    emit(@{@"status": unsupported ? @"SKIP" : (action == kAXErrorSuccess ? @"PASS" : @"FAIL"),
           @"accessibility":@YES,
           @"target":@"Finder",
           @"window_title":title ?: @"",
           @"window_index":@(selected),
           @"window_count":@(count),
           @"action":actionName,
           @"ax_error":@(action),
           @"reason":unsupported ? @"no_safe_supported_mutating_action" : @""});
    CFRelease(windows);
    CFRelease(app);
    return (action == kAXErrorSuccess || unsupported) ? 0 : 1;
}

static NSString *axStringAttribute(AXUIElementRef element, CFStringRef attribute) {
    CFTypeRef value = NULL;
    AXError rc = AXUIElementCopyAttributeValue(element, attribute, &value);
    NSString *out = @"";
    if (rc == kAXErrorSuccess && value && CFGetTypeID(value) == CFStringGetTypeID()) {
        out = [(__bridge NSString *)value copy];
    }
    if (value) CFRelease(value);
    return out;
}

static NSDictionary *axFrame(AXUIElementRef element) {
    CGPoint p = CGPointZero;
    CGSize s = CGSizeZero;
    BOOL haveP = NO, haveS = NO;
    CFTypeRef pv = NULL, sv = NULL;
    if (AXUIElementCopyAttributeValue(element, kAXPositionAttribute, &pv) == kAXErrorSuccess && pv && CFGetTypeID(pv) == AXValueGetTypeID()) {
        haveP = AXValueGetValue((AXValueRef)pv, kAXValueCGPointType, &p);
    }
    if (AXUIElementCopyAttributeValue(element, kAXSizeAttribute, &sv) == kAXErrorSuccess && sv && CFGetTypeID(sv) == AXValueGetTypeID()) {
        haveS = AXValueGetValue((AXValueRef)sv, kAXValueCGSizeType, &s);
    }
    if (pv) CFRelease(pv);
    if (sv) CFRelease(sv);
    if (!haveP && !haveS) return @{};
    return @{@"x":@(p.x), @"y":@(p.y), @"width":@(s.width), @"height":@(s.height)};
}

static NSArray *axActionNames(AXUIElementRef element) {
    CFArrayRef actions = NULL;
    if (AXUIElementCopyActionNames(element, &actions) != kAXErrorSuccess || !actions) return @[];
    NSMutableArray *out = [NSMutableArray array];
    CFIndex n = MIN(CFArrayGetCount(actions), 12);
    for (CFIndex i = 0; i < n; i++) {
        CFTypeRef v = CFArrayGetValueAtIndex(actions, i);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) [out addObject:(__bridge NSString *)v];
    }
    CFRelease(actions);
    return out;
}

static NSDictionary *axElementSummary(AXUIElementRef element) {
    NSString *role = axStringAttribute(element, kAXRoleAttribute);
    NSString *subrole = axStringAttribute(element, kAXSubroleAttribute);
    NSString *title = axStringAttribute(element, kAXTitleAttribute);
    NSString *desc = axStringAttribute(element, kAXDescriptionAttribute);
    NSString *value = axStringAttribute(element, kAXValueAttribute);
    BOOL valueTruncated = NO;
    if (value.length > 512) {
        value = [[value substringToIndex:512] stringByAppendingString:@"…"];
        valueTruncated = YES;
    }
    BOOL focused = NO;
    CFTypeRef focusedValue = NULL;
    if (AXUIElementCopyAttributeValue(element, kAXFocusedAttribute, &focusedValue) == kAXErrorSuccess && focusedValue && CFGetTypeID(focusedValue) == CFBooleanGetTypeID()) {
        focused = CFBooleanGetValue((CFBooleanRef)focusedValue);
    }
    if (focusedValue) CFRelease(focusedValue);
    return @{@"role":role ?: @"", @"subrole":subrole ?: @"", @"title":title ?: @"", @"description":desc ?: @"", @"value":value ?: @"", @"value_truncated":@(valueTruncated), @"focused":@(focused), @"frame":axFrame(element), @"actions":axActionNames(element)};
}

static NSDictionary *axElementTree(AXUIElementRef element,
                                   NSUInteger depth,
                                   NSUInteger maxDepth,
                                   NSUInteger *nodeCount,
                                   NSUInteger maxNodes,
                                   BOOL *truncated,
                                   NSString *ref) {
    NSMutableDictionary *summary = [[axElementSummary(element) mutableCopy] ?: [NSMutableDictionary dictionary] mutableCopy];
    summary[@"ref"] = ref ?: @"";
    if (*nodeCount >= maxNodes) {
        *truncated = YES;
        return summary;
    }
    (*nodeCount)++;
    if (depth >= maxDepth) return summary;

    CFTypeRef childrenValue = NULL;
    AXError rc = AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &childrenValue);
    if (rc != kAXErrorSuccess || !childrenValue || CFGetTypeID(childrenValue) != CFArrayGetTypeID()) {
        if (childrenValue) CFRelease(childrenValue);
        return summary;
    }

    CFArrayRef children = (CFArrayRef)childrenValue;
    NSMutableArray *childrenOut = [NSMutableArray array];
    CFIndex count = CFArrayGetCount(children);
    for (CFIndex i = 0; i < count; i++) {
        if (*nodeCount >= maxNodes) {
            *truncated = YES;
            break;
        }
        AXUIElementRef child = (AXUIElementRef)CFArrayGetValueAtIndex(children, i);
        NSString *childRef = [NSString stringWithFormat:@"%@/c%ld", ref ?: @"", (long)i];
        [childrenOut addObject:axElementTree(child, depth + 1, maxDepth, nodeCount, maxNodes, truncated, childRef)];
    }
    CFRelease(childrenValue);
    if (childrenOut.count > 0) summary[@"children"] = childrenOut;
    return summary;
}

static int accessibilityInventory(void) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (!front) {
        emit(@{@"status":@"FAIL", @"reason":@"no_frontmost_application"});
        return 1;
    }

    const NSUInteger maxDepth = 3;
    const NSUInteger maxNodes = 120;
    AXUIElementRef app = AXUIElementCreateApplication(front.processIdentifier);
    CFTypeRef windowsValue = NULL;
    AXError rc = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windowsValue);
    NSMutableArray *windowsOut = [NSMutableArray array];
    NSUInteger nodeCount = 0;
    BOOL truncated = NO;

    if (rc == kAXErrorSuccess && windowsValue && CFGetTypeID(windowsValue) == CFArrayGetTypeID()) {
        CFArrayRef windows = (CFArrayRef)windowsValue;
        CFIndex wn = MIN(CFArrayGetCount(windows), 8);
        for (CFIndex i = 0; i < wn; i++) {
            if (nodeCount >= maxNodes) { truncated = YES; break; }
            AXUIElementRef win = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
            NSString *ref = [NSString stringWithFormat:@"w%ld", (long)i];
            [windowsOut addObject:axElementTree(win, 0, maxDepth, &nodeCount, maxNodes, &truncated, ref)];
        }
        if (CFArrayGetCount(windows) > wn) truncated = YES;
    }
    if (windowsValue) CFRelease(windowsValue);
    CFRelease(app);

    emit(@{@"status":rc == kAXErrorSuccess ? @"PASS" : @"FAIL",
           @"accessibility":@YES,
           @"application":front.localizedName ?: @"",
           @"bundle_id":front.bundleIdentifier ?: @"",
           @"pid":@(front.processIdentifier),
           @"node_count":@(nodeCount),
           @"max_nodes":@(maxNodes),
           @"max_depth":@(maxDepth),
           @"truncated":@(truncated),
           @"ref_scope":@"current_ax_tree_only",
           @"windows":windowsOut,
           @"ax_error":@(rc)});
    return rc == kAXErrorSuccess ? 0 : 1;
}

static BOOL axSelectorMatches(AXUIElementRef element,
                              NSString *role,
                              NSString *subrole,
                              NSString *title,
                              NSString *desc,
                              NSString *value) {
    BOOL any = NO;
    if (role.length > 0) {
        any = YES;
        if (![axStringAttribute(element, kAXRoleAttribute) isEqualToString:role]) return NO;
    }
    if (subrole.length > 0) {
        any = YES;
        if (![axStringAttribute(element, kAXSubroleAttribute) isEqualToString:subrole]) return NO;
    }
    if (title.length > 0) {
        any = YES;
        if (![axStringAttribute(element, kAXTitleAttribute) isEqualToString:title]) return NO;
    }
    if (desc.length > 0) {
        any = YES;
        if (![axStringAttribute(element, kAXDescriptionAttribute) isEqualToString:desc]) return NO;
    }
    if (value.length > 0) {
        any = YES;
        if (![axStringAttribute(element, kAXValueAttribute) isEqualToString:value]) return NO;
    }
    return any;
}

static void axFindMatches(AXUIElementRef element,
                          NSString *ref,
                          NSUInteger depth,
                          NSUInteger maxDepth,
                          NSUInteger *nodeCount,
                          NSUInteger maxNodes,
                          BOOL *truncated,
                          NSString *role,
                          NSString *subrole,
                          NSString *title,
                          NSString *desc,
                          NSString *value,
                          NSMutableArray *summaries,
                          CFMutableArrayRef elements) {
    if (*nodeCount >= maxNodes || summaries.count >= 20) {
        *truncated = YES;
        return;
    }
    (*nodeCount)++;
    if (axSelectorMatches(element, role, subrole, title, desc, value)) {
        NSMutableDictionary *summary = [[axElementSummary(element) mutableCopy] ?: [NSMutableDictionary dictionary] mutableCopy];
        summary[@"ref"] = ref ?: @"";
        [summaries addObject:summary];
        CFArrayAppendValue(elements, element);
    }
    if (depth >= maxDepth) return;

    CFTypeRef childrenValue = NULL;
    AXError rc = AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &childrenValue);
    if (rc != kAXErrorSuccess || !childrenValue || CFGetTypeID(childrenValue) != CFArrayGetTypeID()) {
        if (childrenValue) CFRelease(childrenValue);
        return;
    }
    CFArrayRef children = (CFArrayRef)childrenValue;
    CFIndex count = CFArrayGetCount(children);
    for (CFIndex i = 0; i < count; i++) {
        if (*nodeCount >= maxNodes || summaries.count >= 20) {
            *truncated = YES;
            break;
        }
        AXUIElementRef child = (AXUIElementRef)CFArrayGetValueAtIndex(children, i);
        NSString *childRef = [NSString stringWithFormat:@"%@/c%ld", ref ?: @"", (long)i];
        axFindMatches(child, childRef, depth + 1, maxDepth, nodeCount, maxNodes, truncated,
                      role, subrole, title, desc, value, summaries, elements);
    }
    CFRelease(childrenValue);
}

@interface AXEventWatchContext : NSObject
@property(nonatomic, strong) NSMutableArray *events;
@property(nonatomic, strong) NSMutableArray *registrations;
@property(nonatomic, strong) NSMutableArray<NSValue *> *retainedElements;
@property(nonatomic, strong) NSSet<NSString *> *requestedNames;
@property(nonatomic, assign) NSInteger eventLimit;
@property(nonatomic, assign) BOOL fixedElementTarget;
@property(nonatomic, assign) AXObserverRef observer;
@property(nonatomic, assign) AXUIElementRef appElement;
@end

@implementation AXEventWatchContext
@end

static NSString *axEventFriendlyName(CFStringRef notification) {
    if (CFEqual(notification, kAXWindowCreatedNotification)) return @"window-created";
    if (CFEqual(notification, kAXFocusedWindowChangedNotification)) return @"focused-window-changed";
    if (CFEqual(notification, kAXFocusedUIElementChangedNotification)) return @"focused-ui-element-changed";
    if (CFEqual(notification, kAXMainWindowChangedNotification)) return @"main-window-changed";
    if (CFEqual(notification, kAXApplicationActivatedNotification)) return @"application-activated";
    if (CFEqual(notification, kAXApplicationDeactivatedNotification)) return @"application-deactivated";
    if (CFEqual(notification, kAXApplicationHiddenNotification)) return @"application-hidden";
    if (CFEqual(notification, kAXApplicationShownNotification)) return @"application-shown";
    if (CFEqual(notification, kAXValueChangedNotification)) return @"value-changed";
    if (CFEqual(notification, kAXMovedNotification)) return @"moved";
    if (CFEqual(notification, kAXResizedNotification)) return @"resized";
    if (CFEqual(notification, kAXSelectedChildrenChangedNotification)) return @"selected-children-changed";
    if (CFEqual(notification, kAXUIElementDestroyedNotification)) return @"ui-element-destroyed";
    return (__bridge NSString *)notification ?: @"unknown";
}

static CFStringRef axNotificationForEventName(NSString *name) {
    if ([name isEqualToString:@"window-created"]) return kAXWindowCreatedNotification;
    if ([name isEqualToString:@"focused-window-changed"]) return kAXFocusedWindowChangedNotification;
    if ([name isEqualToString:@"focused-ui-element-changed"]) return kAXFocusedUIElementChangedNotification;
    if ([name isEqualToString:@"main-window-changed"]) return kAXMainWindowChangedNotification;
    if ([name isEqualToString:@"application-activated"]) return kAXApplicationActivatedNotification;
    if ([name isEqualToString:@"application-deactivated"]) return kAXApplicationDeactivatedNotification;
    if ([name isEqualToString:@"application-hidden"]) return kAXApplicationHiddenNotification;
    if ([name isEqualToString:@"application-shown"]) return kAXApplicationShownNotification;
    if ([name isEqualToString:@"value-changed"]) return kAXValueChangedNotification;
    if ([name isEqualToString:@"moved"]) return kAXMovedNotification;
    if ([name isEqualToString:@"resized"]) return kAXResizedNotification;
    if ([name isEqualToString:@"selected-children-changed"]) return kAXSelectedChildrenChangedNotification;
    if ([name isEqualToString:@"ui-element-destroyed"]) return kAXUIElementDestroyedNotification;
    return NULL;
}

static BOOL axEventIsApplicationScoped(NSString *name) {
    return [@[@"window-created", @"focused-window-changed", @"focused-ui-element-changed",
              @"main-window-changed", @"application-activated", @"application-deactivated",
              @"application-hidden", @"application-shown"] containsObject:name];
}

static BOOL axEventUsesFocusedUIElement(NSString *name) {
    return [@[@"value-changed", @"selected-children-changed", @"ui-element-destroyed"] containsObject:name];
}

static BOOL axEventUsesFocusedWindow(NSString *name) {
    return [@[@"moved", @"resized"] containsObject:name];
}

static NSString *axISO8601Now(void) {
    NSISO8601DateFormatter *fmt = [[NSISO8601DateFormatter alloc] init];
    return [fmt stringFromDate:[NSDate date]];
}

static AXUIElementRef axCopyElementAttribute(AXUIElementRef element, CFStringRef attribute) {
    CFTypeRef value = NULL;
    AXError rc = AXUIElementCopyAttributeValue(element, attribute, &value);
    if (rc != kAXErrorSuccess || !value || CFGetTypeID(value) != AXUIElementGetTypeID()) {
        if (value) CFRelease(value);
        return NULL;
    }
    return (AXUIElementRef)value;
}

static void axWatchRetainElement(AXEventWatchContext *ctx, AXUIElementRef element) {
    if (!element) return;
    CFRetain(element);
    [ctx.retainedElements addObject:[NSValue valueWithPointer:element]];
}

static BOOL axWatchRegister(AXEventWatchContext *ctx,
                            NSString *eventName,
                            AXUIElementRef target,
                            NSString *targetScope,
                            BOOL dependency) {
    if (!ctx.observer || !target) return NO;
    CFStringRef notification = axNotificationForEventName(eventName);
    if (!notification) return NO;
    AXError rc = AXObserverAddNotification(ctx.observer, target, notification, (__bridge void *)ctx);
    BOOL registered = (rc == kAXErrorSuccess || rc == kAXErrorNotificationAlreadyRegistered);
    [ctx.registrations addObject:@{
        @"event": eventName,
        @"notification": (__bridge NSString *)notification,
        @"target_scope": targetScope ?: @"unknown",
        @"dependency": @(dependency),
        @"registered": @(registered),
        @"ax_error": @(rc)
    }];
    if (rc == kAXErrorSuccess) axWatchRetainElement(ctx, target);
    return registered;
}

static void axWatchRegisterDynamicTargets(AXEventWatchContext *ctx) {
    if (!ctx || ctx.fixedElementTarget) return;
    BOOL wantsFocusedElement = NO;
    BOOL wantsFocusedWindow = NO;
    for (NSString *name in ctx.requestedNames) {
        if (axEventUsesFocusedUIElement(name)) wantsFocusedElement = YES;
        if (axEventUsesFocusedWindow(name)) wantsFocusedWindow = YES;
    }
    if (wantsFocusedElement) {
        AXUIElementRef focused = axCopyElementAttribute(ctx.appElement, kAXFocusedUIElementAttribute);
        if (focused) {
            for (NSString *name in ctx.requestedNames) {
                if (axEventUsesFocusedUIElement(name)) axWatchRegister(ctx, name, focused, @"focused-ui-element", NO);
            }
            CFRelease(focused);
        }
    }
    if (wantsFocusedWindow) {
        AXUIElementRef window = axCopyElementAttribute(ctx.appElement, kAXFocusedWindowAttribute);
        if (window) {
            for (NSString *name in ctx.requestedNames) {
                if (axEventUsesFocusedWindow(name)) axWatchRegister(ctx, name, window, @"focused-window", NO);
            }
            CFRelease(window);
        }
    }
}

static void axObserverEventCallback(AXObserverRef observer,
                                    AXUIElementRef element,
                                    CFStringRef notification,
                                    void *refcon) {
    AXEventWatchContext *ctx = (__bridge AXEventWatchContext *)refcon;
    if (!ctx) return;
    NSString *friendly = axEventFriendlyName(notification);

    if (!ctx.fixedElementTarget && CFEqual(notification, kAXFocusedUIElementChangedNotification)) {
        axWatchRegisterDynamicTargets(ctx);
    }
    if (!ctx.fixedElementTarget && (CFEqual(notification, kAXFocusedWindowChangedNotification) || CFEqual(notification, kAXWindowCreatedNotification))) {
        axWatchRegisterDynamicTargets(ctx);
    }

    if (![ctx.requestedNames containsObject:friendly]) return;
    NSMutableDictionary *event = [NSMutableDictionary dictionary];
    event[@"event"] = friendly;
    event[@"notification"] = (__bridge NSString *)notification ?: @"";
    event[@"timestamp"] = axISO8601Now();
    event[@"element"] = axElementSummary(element) ?: @{};
    [ctx.events addObject:event];
    if (ctx.events.count >= (NSUInteger)MAX(1, ctx.eventLimit)) {
        CFRunLoopStop(CFRunLoopGetCurrent());
    }
}

static NSArray<NSString *> *axParseEventNames(NSString *csv, NSString **invalidOut) {
    NSString *source = csv.length > 0 ? csv : @"window-created,focused-window-changed,focused-ui-element-changed,main-window-changed,application-activated";
    NSMutableArray *names = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    for (NSString *raw in [source componentsSeparatedByString:@","]) {
        NSString *name = [[raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
        if (name.length == 0) continue;
        if (!axNotificationForEventName(name)) {
            if (invalidOut) *invalidOut = name;
            return nil;
        }
        if (![seen containsObject:name]) {
            [names addObject:name];
            [seen addObject:name];
        }
    }
    return names;
}

static AXUIElementRef axResolveExactObservedElement(AXUIElementRef app,
                                                    NSString *role,
                                                    NSString *subrole,
                                                    NSString *title,
                                                    NSString *desc,
                                                    NSString *value,
                                                    NSDictionary **resolutionOut) {
    const NSUInteger maxDepth = 8;
    const NSUInteger maxNodes = 500;
    NSUInteger nodeCount = 0;
    BOOL truncated = NO;
    NSMutableArray *matches = [NSMutableArray array];
    CFMutableArrayRef elements = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFTypeRef windowsValue = NULL;
    AXError rc = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windowsValue);
    if (rc == kAXErrorSuccess && windowsValue && CFGetTypeID(windowsValue) == CFArrayGetTypeID()) {
        CFArrayRef windows = (CFArrayRef)windowsValue;
        CFIndex count = MIN(CFArrayGetCount(windows), 12);
        for (CFIndex i = 0; i < count; i++) {
            AXUIElementRef win = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
            NSString *ref = [NSString stringWithFormat:@"w%ld", (long)i];
            axFindMatches(win, ref, 0, maxDepth, &nodeCount, maxNodes, &truncated,
                          role, subrole, title, desc, value, matches, elements);
        }
    }
    AXUIElementRef resolved = NULL;
    if (matches.count == 1 && CFArrayGetCount(elements) == 1) {
        resolved = (AXUIElementRef)CFArrayGetValueAtIndex(elements, 0);
        CFRetain(resolved);
    }
    if (resolutionOut) {
        *resolutionOut = @{
            @"ax_error": @(rc),
            @"match_count": @(matches.count),
            @"node_count": @(nodeCount),
            @"truncated": @(truncated),
            @"matches": matches
        };
    }
    if (windowsValue) CFRelease(windowsValue);
    CFRelease(elements);
    return resolved;
}

static int accessibilityEventObserve(BOOL requireEvent,
                                     NSString *bundleID,
                                     NSString *eventsCSV,
                                     NSString *role,
                                     NSString *subrole,
                                     NSString *title,
                                     NSString *desc,
                                     NSString *value,
                                     NSTimeInterval observeSeconds,
                                     NSInteger eventLimit) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    if (observeSeconds <= 0 || observeSeconds > 60 || eventLimit < 1 || eventLimit > 200) {
        emit(@{@"status":@"FAIL", @"reason":@"invalid_event_watch_limits"});
        return 64;
    }
    NSString *invalid = nil;
    NSArray<NSString *> *eventNames = axParseEventNames(eventsCSV, &invalid);
    if (!eventNames || eventNames.count == 0) {
        emit(@{@"status":@"FAIL", @"reason":@"invalid_event_name", @"event":invalid ?: @""});
        return 64;
    }

    NSRunningApplication *targetApp = bundleID.length > 0 ? runningApp(bundleID) : NSWorkspace.sharedWorkspace.frontmostApplication;
    if (!targetApp) {
        emit(@{@"status":@"FAIL", @"reason":@"target_application_not_running", @"bundle_id":bundleID ?: @""});
        return 1;
    }
    NSString *actualBundle = targetApp.bundleIdentifier ?: @"";
    if (bundleID.length > 0 && ![actualBundle isEqualToString:bundleID]) {
        emit(@{@"status":@"FAIL", @"reason":@"bundle_mismatch", @"expected_bundle":bundleID, @"actual_bundle":actualBundle});
        return 1;
    }

    AXUIElementRef app = AXUIElementCreateApplication(targetApp.processIdentifier);
    AXObserverRef observer = NULL;
    AXError createRC = AXObserverCreate(targetApp.processIdentifier, axObserverEventCallback, &observer);
    if (createRC != kAXErrorSuccess || !observer) {
        if (app) CFRelease(app);
        emit(@{@"status":@"FAIL", @"reason":@"ax_observer_create_failed", @"ax_error":@(createRC), @"pid":@(targetApp.processIdentifier)});
        return 1;
    }

    AXEventWatchContext *ctx = [AXEventWatchContext new];
    ctx.events = [NSMutableArray array];
    ctx.registrations = [NSMutableArray array];
    ctx.retainedElements = [NSMutableArray array];
    ctx.requestedNames = [NSSet setWithArray:eventNames];
    ctx.eventLimit = eventLimit;
    ctx.observer = observer;
    ctx.appElement = app;
    BOOL hasSelector = role.length > 0 || subrole.length > 0 || title.length > 0 || desc.length > 0 || value.length > 0;
    ctx.fixedElementTarget = hasSelector;

    AXUIElementRef fixedTarget = NULL;
    NSDictionary *resolution = nil;
    if (hasSelector) {
        fixedTarget = axResolveExactObservedElement(app, role, subrole, title, desc, value, &resolution);
        if (!fixedTarget) {
            NSDictionary *out = @{
                @"status":@"FAIL",
                @"reason":([resolution[@"match_count"] integerValue] == 0 ? @"no_observer_target_match" : @"ambiguous_observer_target"),
                @"bundle_id":actualBundle,
                @"selector_resolution":resolution ?: @{}
            };
            emit(out);
            CFRelease(observer);
            CFRelease(app);
            return [resolution[@"match_count"] integerValue] > 1 ? 65 : 1;
        }
    }

    NSUInteger requestedRegistrationSuccess = 0;
    for (NSString *name in eventNames) {
        BOOL ok = NO;
        if (axEventIsApplicationScoped(name)) {
            ok = axWatchRegister(ctx, name, app, @"application", NO);
        } else if (fixedTarget) {
            ok = axWatchRegister(ctx, name, fixedTarget, @"exact-selector", NO);
        }
        if (ok) requestedRegistrationSuccess++;
    }

    if (!fixedTarget) {
        BOOL needsFocusedElementDependency = NO;
        BOOL needsFocusedWindowDependency = NO;
        for (NSString *name in eventNames) {
            if (axEventUsesFocusedUIElement(name)) needsFocusedElementDependency = YES;
            if (axEventUsesFocusedWindow(name)) needsFocusedWindowDependency = YES;
        }
        if (needsFocusedElementDependency && ![ctx.requestedNames containsObject:@"focused-ui-element-changed"]) {
            axWatchRegister(ctx, @"focused-ui-element-changed", app, @"application", YES);
        }
        if (needsFocusedWindowDependency && ![ctx.requestedNames containsObject:@"focused-window-changed"]) {
            axWatchRegister(ctx, @"focused-window-changed", app, @"application", YES);
        }
        NSUInteger before = ctx.registrations.count;
        axWatchRegisterDynamicTargets(ctx);
        for (NSUInteger i = before; i < ctx.registrations.count; i++) {
            NSDictionary *reg = ctx.registrations[i];
            if ([reg[@"registered"] boolValue] && ![reg[@"dependency"] boolValue]) requestedRegistrationSuccess++;
        }
    }

    if (fixedTarget) CFRelease(fixedTarget);
    if (requestedRegistrationSuccess == 0) {
        emit(@{@"status":@"FAIL", @"reason":@"no_requested_event_registration_succeeded",
               @"bundle_id":actualBundle, @"registrations":ctx.registrations});
        for (NSValue *v in ctx.retainedElements) CFRelease((CFTypeRef)[v pointerValue]);
        CFRelease(observer);
        CFRelease(app);
        return 1;
    }

    CFRunLoopSourceRef source = AXObserverGetRunLoopSource(observer);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:observeSeconds];
    while ([[NSDate date] compare:deadline] == NSOrderedAscending && ctx.events.count < (NSUInteger)eventLimit) {
        NSTimeInterval remaining = [deadline timeIntervalSinceNow];
        if (remaining <= 0) break;
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, MIN(0.10, remaining), true);
    }
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);

    BOOL gotEvent = ctx.events.count > 0;
    NSString *status = (requireEvent && !gotEvent) ? @"TIMEOUT" : @"PASS";
    NSMutableDictionary *out = [@{
        @"status":status,
        @"operation":requireEvent ? @"event_wait" : @"event_observe",
        @"backend":@"AXObserver",
        @"application":targetApp.localizedName ?: @"",
        @"bundle_id":actualBundle,
        @"pid":@(targetApp.processIdentifier),
        @"observe_seconds":@(observeSeconds),
        @"event_limit":@(eventLimit),
        @"requested_events":eventNames,
        @"event_count":@(ctx.events.count),
        @"events":ctx.events,
        @"registrations":ctx.registrations,
        @"selector_resolution":resolution ?: [NSNull null],
        @"action_time_re_resolution_required":@YES
    } mutableCopy];
    if (requireEvent && !gotEvent) out[@"reason"] = @"event_wait_timeout";
    emit(out);

    for (NSValue *v in ctx.retainedElements) CFRelease((CFTypeRef)[v pointerValue]);
    CFRelease(observer);
    CFRelease(app);
    return (requireEvent && !gotEvent) ? 75 : 0;
}

static int accessibilitySemantic(BOOL press,
                                 NSString *expectedBundle,
                                 NSString *role,
                                 NSString *subrole,
                                 NSString *title,
                                 NSString *desc,
                                 NSString *value) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    if (role.length == 0 && subrole.length == 0 && title.length == 0 && desc.length == 0 && value.length == 0) {
        emit(@{@"status":@"FAIL", @"reason":@"missing_selector"});
        return 64;
    }
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (!front) {
        emit(@{@"status":@"FAIL", @"reason":@"no_frontmost_application"});
        return 1;
    }
    NSString *bundle = front.bundleIdentifier ?: @"";
    if (expectedBundle.length > 0 && ![bundle isEqualToString:expectedBundle]) {
        emit(@{@"status":@"FAIL", @"reason":@"frontmost_bundle_mismatch", @"expected_bundle":expectedBundle, @"actual_bundle":bundle});
        return 1;
    }

    const NSUInteger maxDepth = 8;
    const NSUInteger maxNodes = 500;
    NSUInteger nodeCount = 0;
    BOOL truncated = NO;
    NSMutableArray *matches = [NSMutableArray array];
    CFMutableArrayRef elements = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    AXUIElementRef app = AXUIElementCreateApplication(front.processIdentifier);
    CFTypeRef windowsValue = NULL;
    AXError rc = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &windowsValue);
    if (rc == kAXErrorSuccess && windowsValue && CFGetTypeID(windowsValue) == CFArrayGetTypeID()) {
        CFArrayRef windows = (CFArrayRef)windowsValue;
        CFIndex count = MIN(CFArrayGetCount(windows), 12);
        for (CFIndex i = 0; i < count; i++) {
            AXUIElementRef win = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
            NSString *ref = [NSString stringWithFormat:@"w%ld", (long)i];
            axFindMatches(win, ref, 0, maxDepth, &nodeCount, maxNodes, &truncated,
                          role, subrole, title, desc, value, matches, elements);
        }
        if (CFArrayGetCount(windows) > count) truncated = YES;
    }

    NSMutableDictionary *result = [@{@"status":@"PASS", @"operation":press ? @"semantic_press" : @"semantic_find",
                                     @"application":front.localizedName ?: @"", @"bundle_id":bundle,
                                     @"pid":@(front.processIdentifier), @"match_count":@(matches.count),
                                     @"node_count":@(nodeCount), @"max_nodes":@(maxNodes), @"max_depth":@(maxDepth),
                                     @"truncated":@(truncated), @"matches":matches} mutableCopy];
    int exitCode = 0;
    if (rc != kAXErrorSuccess) {
        result[@"status"] = @"FAIL";
        result[@"reason"] = @"ax_windows_failed";
        result[@"ax_error"] = @(rc);
        exitCode = 1;
    } else if (press) {
        if (matches.count == 0) {
            result[@"status"] = @"FAIL";
            result[@"reason"] = @"no_match";
            exitCode = 1;
        } else if (matches.count != 1) {
            result[@"status"] = @"FAIL";
            result[@"reason"] = @"ambiguous_selector";
            exitCode = 65;
        } else {
            AXUIElementRef target = (AXUIElementRef)CFArrayGetValueAtIndex(elements, 0);
            NSArray *actions = axActionNames(target);
            if (![actions containsObject:(__bridge NSString *)kAXPressAction]) {
                result[@"status"] = @"FAIL";
                result[@"reason"] = @"axpress_unsupported";
                exitCode = 1;
            } else {
                AXError actionRC = AXUIElementPerformAction(target, kAXPressAction);
                result[@"action"] = @"AXPress";
                result[@"ax_error"] = @(actionRC);
                if (actionRC != kAXErrorSuccess) {
                    result[@"status"] = @"FAIL";
                    result[@"reason"] = @"axpress_failed";
                    exitCode = 1;
                }
            }
        }
    }
    if (windowsValue) CFRelease(windowsValue);
    CFRelease(app);
    CFRelease(elements);
    emit(result);
    return exitCode;
}

static NSDictionary *visionOCR(CGImageRef image) {
    VNRecognizeTextRequest *request = [VNRecognizeTextRequest new];
    request.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
    request.usesLanguageCorrection = YES;
    request.automaticallyDetectsLanguage = YES;
    NSError *languageError = nil;
    NSArray<NSString *> *supported = [request supportedRecognitionLanguagesAndReturnError:&languageError] ?: @[];
    NSMutableArray<NSString *> *preferred = [NSMutableArray array];
    for (NSString *lang in @[@"zh-Hans", @"zh-Hant", @"en-US"]) {
        if ([supported containsObject:lang]) [preferred addObject:lang];
    }
    if (preferred.count > 0) request.recognitionLanguages = preferred;
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:image options:@{}];
    NSError *error = nil;
    BOOL performed = [handler performRequests:@[request] error:&error];
    if (!performed || error) {
        return @{@"status":@"FAIL", @"reason":error.localizedDescription ?: @"vision_request_failed", @"items":@[]};
    }
    NSMutableArray *items = [NSMutableArray array];
    NSArray<VNRecognizedTextObservation *> *observations = request.results ?: @[];
    NSUInteger limit = MIN(observations.count, 80);
    for (NSUInteger i = 0; i < limit; i++) {
        VNRecognizedTextObservation *obs = observations[i];
        VNRecognizedText *candidate = [obs topCandidates:1].firstObject;
        if (!candidate || candidate.string.length == 0) continue;
        CGRect b = obs.boundingBox;
        [items addObject:@{@"text":candidate.string,
                           @"confidence":@(candidate.confidence),
                           @"box":@{@"x":@(b.origin.x), @"y":@(b.origin.y), @"width":@(b.size.width), @"height":@(b.size.height)}}];
    }
    return @{@"status":@"PASS", @"count":@(items.count), @"truncated":@(observations.count > limit), @"items":items};
}

static int guiTypeText(NSString *text) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    if (text.length == 0) {
        emit(@{@"status":@"FAIL", @"reason":@"empty_text"});
        return 64;
    }
    if (text.length > 4096) {
        emit(@{@"status":@"FAIL", @"reason":@"text_too_large", @"max_utf16_units":@4096});
        return 64;
    }
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    NSUInteger i = 0;
    NSUInteger events = 0;
    while (i < text.length) {
        NSRange range = [text rangeOfComposedCharacterSequenceAtIndex:i];
        UniChar chars[16] = {0};
        if (range.length == 0 || range.length > 16) {
            emit(@{@"status":@"FAIL", @"reason":@"unsupported_grapheme_length", @"length":@(range.length)});
            return 1;
        }
        [text getCharacters:chars range:range];
        CGEventRef down = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)0, true);
        CGEventRef up = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)0, false);
        if (!down || !up) {
            if (down) CFRelease(down);
            if (up) CFRelease(up);
            emit(@{@"status":@"FAIL", @"reason":@"event_create_failed"});
            return 1;
        }
        CGEventKeyboardSetUnicodeString(down, range.length, chars);
        CGEventKeyboardSetUnicodeString(up, range.length, chars);
        CGEventPost(kCGHIDEventTap, down);
        usleep(2500);
        CGEventPost(kCGHIDEventTap, up);
        CFRelease(down);
        CFRelease(up);
        events++;
        i = NSMaxRange(range);
        usleep(2500);
    }
    emit(@{@"status":@"PASS", @"accessibility":@YES, @"operation":@"type_text", @"utf16_units":@(text.length), @"event_pairs":@(events), @"target_pid":front ? @(front.processIdentifier) : @0, @"target_bundle":front.bundleIdentifier ?: @""});
    return 0;
}

static CGEventFlags guiModifierFlags(NSString *modifiers) {
    CGEventFlags flags = 0;
    for (NSString *raw in [modifiers componentsSeparatedByString:@","]) {
        NSString *m = [raw.lowercaseString stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([m isEqualToString:@"command"] || [m isEqualToString:@"cmd"]) flags |= kCGEventFlagMaskCommand;
        else if ([m isEqualToString:@"shift"]) flags |= kCGEventFlagMaskShift;
        else if ([m isEqualToString:@"option"] || [m isEqualToString:@"alt"]) flags |= kCGEventFlagMaskAlternate;
        else if ([m isEqualToString:@"control"] || [m isEqualToString:@"ctrl"]) flags |= kCGEventFlagMaskControl;
        else if ([m isEqualToString:@"fn"] || [m isEqualToString:@"function"]) flags |= kCGEventFlagMaskSecondaryFn;
    }
    return flags;
}

static int guiKeyPress(CGKeyCode keycode, NSString *modifiers) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    CGEventFlags flags = guiModifierFlags(modifiers ?: @"");
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, keycode, true);
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, keycode, false);
    if (!down || !up) {
        if (down) CFRelease(down);
        if (up) CFRelease(up);
        emit(@{@"status":@"FAIL", @"reason":@"event_create_failed"});
        return 1;
    }
    CGEventSetFlags(down, flags);
    CGEventSetFlags(up, flags);
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (front) {
        CGEventPostToPid(front.processIdentifier, down);
        usleep(12000);
        CGEventPostToPid(front.processIdentifier, up);
    } else {
        CGEventPost(kCGHIDEventTap, down);
        usleep(12000);
        CGEventPost(kCGHIDEventTap, up);
    }
    CFRelease(down);
    CFRelease(up);
    emit(@{@"status":@"PASS", @"accessibility":@YES, @"operation":@"key_press", @"keycode":@(keycode), @"modifiers":modifiers ?: @"", @"target_pid":front ? @(front.processIdentifier) : @0, @"target_bundle":front.bundleIdentifier ?: @""});
    return 0;
}

static CGMouseButton guiMouseButton(NSString *button) {
    if ([button.lowercaseString isEqualToString:@"right"]) return kCGMouseButtonRight;
    if ([button.lowercaseString isEqualToString:@"center"] || [button.lowercaseString isEqualToString:@"middle"]) return kCGMouseButtonCenter;
    return kCGMouseButtonLeft;
}

static CGEventType guiMouseDownType(CGMouseButton button) {
    if (button == kCGMouseButtonRight) return kCGEventRightMouseDown;
    if (button == kCGMouseButtonCenter) return kCGEventOtherMouseDown;
    return kCGEventLeftMouseDown;
}

static CGEventType guiMouseUpType(CGMouseButton button) {
    if (button == kCGMouseButtonRight) return kCGEventRightMouseUp;
    if (button == kCGMouseButtonCenter) return kCGEventOtherMouseUp;
    return kCGEventLeftMouseUp;
}

static int guiMouseMove(CGFloat x, CGFloat y) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    CGPoint p = CGPointMake(x, y);
    CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, p, kCGMouseButtonLeft);
    if (!move) {
        emit(@{@"status":@"FAIL", @"reason":@"event_create_failed"});
        return 1;
    }
    CGEventPost(kCGHIDEventTap, move);
    CFRelease(move);
    emit(@{@"status":@"PASS", @"accessibility":@YES, @"operation":@"mouse_move", @"x":@(x), @"y":@(y)});
    return 0;
}

static int guiMouseClick(CGFloat x, CGFloat y, NSString *buttonName, NSInteger count) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    if (count < 1) count = 1;
    if (count > 3) count = 3;
    CGMouseButton button = guiMouseButton(buttonName ?: @"left");
    CGPoint p = CGPointMake(x, y);

    // Keep the physical cursor and the synthetic event location in sync. Chromium
    // can ignore location-only mouse down/up events for some web controls when the
    // actual cursor is still elsewhere. Warp first, emit a move event, then click.
    CGError warpRc = CGWarpMouseCursorPosition(p);
    if (warpRc != kCGErrorSuccess) {
        emit(@{@"status":@"FAIL", @"reason":@"cursor_warp_failed", @"cg_error":@(warpRc)});
        return 1;
    }
    CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, p, button);
    if (move) {
        CGEventPost(kCGHIDEventTap, move);
        CFRelease(move);
    }
    usleep(50000);

    for (NSInteger i = 1; i <= count; i++) {
        CGEventRef down = CGEventCreateMouseEvent(NULL, guiMouseDownType(button), p, button);
        CGEventRef up = CGEventCreateMouseEvent(NULL, guiMouseUpType(button), p, button);
        if (!down || !up) {
            if (down) CFRelease(down);
            if (up) CFRelease(up);
            emit(@{@"status":@"FAIL", @"reason":@"event_create_failed"});
            return 1;
        }
        CGEventSetIntegerValueField(down, kCGMouseEventClickState, i);
        CGEventSetIntegerValueField(up, kCGMouseEventClickState, i);
        CGEventPost(kCGHIDEventTap, down);
        CGEventPost(kCGHIDEventTap, up);
        CFRelease(down);
        CFRelease(up);
        if (i < count) usleep(120000);
    }
    emit(@{@"status":@"PASS", @"accessibility":@YES, @"operation":@"mouse_click", @"x":@(x), @"y":@(y), @"button":buttonName ?: @"left", @"count":@(count)});
    return 0;
}

static int screenCaptureKitCapture(NSString *imageOutputPath, BOOL includeOCR) {
    if (!CGPreflightScreenCaptureAccess()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"screen_recording":@NO, @"backend":@"ScreenCaptureKit"});
        return 2;
    }
    if (@available(macOS 14.0, *)) {
        __block NSDictionary *result = nil;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        [SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:YES completionHandler:^(SCShareableContent *content, NSError *error) {
            if (error || !content || content.displays.count == 0) {
                result = @{@"status":@"FAIL", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"reason":error.localizedDescription ?: @"no_shareable_display"};
                dispatch_semaphore_signal(done);
                return;
            }
            SCDisplay *display = nil;
            CGDirectDisplayID mainID = CGMainDisplayID();
            for (SCDisplay *candidate in content.displays) {
                if (candidate.displayID == mainID) { display = candidate; break; }
            }
            if (!display) display = content.displays.firstObject;
            SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];
            SCStreamConfiguration *configuration = [SCStreamConfiguration new];
            size_t targetWidth = CGDisplayPixelsWide(display.displayID);
            size_t targetHeight = CGDisplayPixelsHigh(display.displayID);
            if (targetWidth > 0) configuration.width = targetWidth;
            if (targetHeight > 0) configuration.height = targetHeight;
            [SCScreenshotManager captureImageWithFilter:filter configuration:configuration completionHandler:^(CGImageRef image, NSError *captureError) {
                if (captureError || !image) {
                    result = @{@"status":@"FAIL", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"reason":captureError.localizedDescription ?: @"capture_returned_null"};
                } else {
                    NSMutableDictionary *ok = [@{@"status":@"PASS", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"display_id":@(display.displayID), @"width":@(CGImageGetWidth(image)), @"height":@(CGImageGetHeight(image))} mutableCopy];
                    if (imageOutputPath.length > 0) {
                        NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithCGImage:image];
                        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
                        NSError *writeError = nil;
                        BOOL wrote = png && [png writeToFile:imageOutputPath options:NSDataWritingAtomic error:&writeError];
                        if (!wrote) {
                            result = @{@"status":@"FAIL", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"reason":writeError.localizedDescription ?: @"png_write_failed"};
                            dispatch_semaphore_signal(done);
                            return;
                        }
                        ok[@"image_path"] = imageOutputPath;
                        ok[@"bytes"] = @(png.length);
                    }
                    if (includeOCR) {
                        ok[@"ocr"] = visionOCR(image);
                    }
                    result = ok;
                }
                dispatch_semaphore_signal(done);
            }];
        }];
        long waitRC = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        if (waitRC != 0 || !result) {
            emit(@{@"status":@"FAIL", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"reason":@"capture_timeout"});
            return 1;
        }
        emit(result);
        return [result[@"status"] isEqualToString:@"PASS"] ? 0 : 1;
    }
    emit(@{@"status":@"UNSUPPORTED", @"screen_recording":@YES, @"backend":@"ScreenCaptureKit", @"reason":@"requires_macos_14"});
    return 3;
}

static int clipboardGet(void) {
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    NSString *text = [pb stringForType:NSPasteboardTypeString] ?: @"";
    emit(@{
        @"status": @"PASS",
        @"operation": @"clipboard_get",
        @"text": text,
        @"length": @(text.length),
        @"change_count": @(pb.changeCount),
    });
    return 0;
}

static NSString *secureTextFromFile(NSString *inputPath, NSString **reasonOut) {
    if (inputPath.length == 0) { if (reasonOut) *reasonOut = @"missing_text_file"; return nil; }
    const char *raw = inputPath.fileSystemRepresentation;
    char resolved[PATH_MAX];
    if (!realpath(raw, resolved)) { if (reasonOut) *reasonOut = @"text_file_realpath_failed"; return nil; }
    NSString *path = [NSString stringWithUTF8String:resolved];
    if (![path hasPrefix:@"/private/tmp/macctl-message-"]) { if (reasonOut) *reasonOut = @"text_file_path_not_allowed"; return nil; }
    struct stat st;
    if (lstat(raw, &st) != 0 || !S_ISREG(st.st_mode)) { if (reasonOut) *reasonOut = @"text_file_not_regular"; return nil; }
    if (st.st_uid != getuid()) { if (reasonOut) *reasonOut = @"text_file_wrong_owner"; return nil; }
    if ((st.st_mode & 077) != 0) { if (reasonOut) *reasonOut = @"text_file_permissions_too_open"; return nil; }
    if (st.st_size <= 0 || st.st_size > 16384) { if (reasonOut) *reasonOut = @"text_file_size_invalid"; return nil; }
    NSError *err = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&err];
    if (!data) { if (reasonOut) *reasonOut = @"text_file_read_failed"; return nil; }
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text || [text rangeOfString:@"\0"].location != NSNotFound) { if (reasonOut) *reasonOut = @"text_file_utf8_invalid"; return nil; }
    if (reasonOut) *reasonOut = nil;
    return text;
}

static BOOL restorePasteboardItems(NSPasteboard *pb, NSArray<NSPasteboardItem *> *items) {
    [pb clearContents];
    if (items.count == 0) return YES;
    return [pb writeObjects:items];
}

static int guiPasteTextPreservingClipboard(NSString *text) {
    if (!AXIsProcessTrusted()) {
        emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
        return 2;
    }
    if (text.length == 0 || text.length > 4096) {
        emit(@{@"status":@"FAIL", @"reason":text.length == 0 ? @"empty_text" : @"text_too_large"});
        return 64;
    }
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    NSMutableArray<NSPasteboardItem *> *saved = [NSMutableArray array];
    for (NSPasteboardItem *item in pb.pasteboardItems ?: @[]) {
        NSPasteboardItem *copy = [[NSPasteboardItem alloc] init];
        for (NSPasteboardType type in item.types ?: @[]) {
            NSData *data = [item dataForType:type];
            if (data) [copy setData:data forType:type];
        }
        [saved addObject:copy];
    }
    [pb clearContents];
    if (![pb setString:text forType:NSPasteboardTypeString]) {
        restorePasteboardItems(pb, saved);
        emit(@{@"status":@"FAIL", @"reason":@"temporary_clipboard_set_failed"});
        return 1;
    }
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)9, true); // V
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)9, false);
    if (!down || !up) {
        if (down) CFRelease(down);
        if (up) CFRelease(up);
        restorePasteboardItems(pb, saved);
        emit(@{@"status":@"FAIL", @"reason":@"paste_event_create_failed"});
        return 1;
    }
    CGEventSetFlags(down, kCGEventFlagMaskCommand);
    CGEventSetFlags(up, kCGEventFlagMaskCommand);
    CGEventPost(kCGHIDEventTap, down);
    usleep(20000);
    CGEventPost(kCGHIDEventTap, up);
    CFRelease(down);
    CFRelease(up);
    usleep(180000);
    BOOL restored = restorePasteboardItems(pb, saved);
    emit(@{@"status":restored ? @"PASS" : @"FAIL",
           @"accessibility":@YES,
           @"operation":@"paste_text_file",
           @"utf16_units":@(text.length),
           @"clipboard_restored":@(restored)});
    return restored ? 0 : 1;
}

static int typeTextFile(NSString *inputPath) {
    NSString *reason = nil;
    NSString *text = secureTextFromFile(inputPath, &reason);
    if (!text) { emit(@{@"status":@"FAIL", @"reason":reason ?: @"text_file_invalid"}); return 64; }
    int rc = guiPasteTextPreservingClipboard(text);
    unlink(inputPath.fileSystemRepresentation);
    return rc;
}

static int clipboardSet(NSString *text) {
    if (!text) {
        emit(@{@"status": @"FAIL", @"reason": @"missing_text"});
        return 64;
    }
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    [pb clearContents];
    BOOL ok = [pb setString:text forType:NSPasteboardTypeString];
    emit(@{
        @"status": ok ? @"PASS" : @"FAIL",
        @"operation": @"clipboard_set",
        @"length": @(text.length),
        @"change_count": @(pb.changeCount),
    });
    return ok ? 0 : 1;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        NSString *cmd = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : @"login-bootstrap";
        NSString *imageOutputPath = nil;
        NSString *textArg = nil;
        NSString *textFileArg = nil;
        NSString *modifiersArg = @"";
        NSString *buttonArg = @"left";
        NSString *bundleArg = @"";
        NSString *roleArg = @"";
        NSString *subroleArg = @"";
        NSString *titleArg = @"";
        NSString *descriptionArg = @"";
        NSString *valueArg = @"";
        NSString *eventsArg = @"";
        NSTimeInterval observeSecondsArg = 3.0;
        NSInteger eventLimitArg = 20;
        CGFloat xArg = NAN, yArg = NAN;
        NSInteger countArg = 1;
        NSInteger keycodeArg = -1;
        for (int i = 2; i < argc; i++) {
            if (i + 1 < argc && strcmp(argv[i], "--output") == 0) {
                gOutputPath = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--image-output") == 0) {
                imageOutputPath = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--text") == 0) {
                textArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--text-file") == 0) {
                textFileArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--modifiers") == 0) {
                modifiersArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--button") == 0) {
                buttonArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--bundle") == 0) {
                bundleArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--role") == 0) {
                roleArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--subrole") == 0) {
                subroleArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--title") == 0) {
                titleArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--description") == 0) {
                descriptionArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--value") == 0) {
                valueArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--events") == 0) {
                eventsArg = [NSString stringWithUTF8String:argv[++i]];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--observe-seconds") == 0) {
                observeSecondsArg = [[NSString stringWithUTF8String:argv[++i]] doubleValue];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--event-limit") == 0) {
                eventLimitArg = [[NSString stringWithUTF8String:argv[++i]] integerValue];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--x") == 0) {
                xArg = [[NSString stringWithUTF8String:argv[++i]] doubleValue];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--y") == 0) {
                yArg = [[NSString stringWithUTF8String:argv[++i]] doubleValue];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--count") == 0) {
                countArg = [[NSString stringWithUTF8String:argv[++i]] integerValue];
                continue;
            }
            if (i + 1 < argc && strcmp(argv[i], "--keycode") == 0) {
                keycodeArg = [[NSString stringWithUTF8String:argv[++i]] integerValue];
                continue;
            }
        }
        if ([cmd isEqualToString:@"login-bootstrap"]) {
            return loginBootstrap();
        }
        if ([cmd isEqualToString:@"lifecycle-status"]) {
            SMAppServiceStatus serviceStatus = [SMAppService mainAppService].status;
            NSMutableDictionary *payload = [lifecycleStatePayload() mutableCopy];
            payload[@"status"] = serviceStatus == SMAppServiceStatusEnabled ? @"PASS" : (serviceStatus == SMAppServiceStatusRequiresApproval ? @"NEEDS_USER_APPROVAL" : @"FAIL");
            payload[@"operation"] = @"lifecycle_status";
            emit(payload);
            return serviceStatus == SMAppServiceStatusEnabled ? 0 : (serviceStatus == SMAppServiceStatusRequiresApproval ? 2 : 1);
        }
        if ([cmd isEqualToString:@"lifecycle-register"]) {
            return lifecycleRegister();
        }
        if ([cmd isEqualToString:@"lifecycle-unregister"]) {
            return lifecycleUnregister();
        }
        if ([cmd isEqualToString:@"status"]) {
            emit(@{@"status":@"PASS",
                   @"accessibility":@(AXIsProcessTrusted()),
                   @"screen_recording":@(CGPreflightScreenCaptureAccess()),
                   @"bundle":NSBundle.mainBundle.bundleIdentifier ?: @"unknown"});
            return 0;
        }
        if ([cmd isEqualToString:@"clipboard-get"]) {
            return clipboardGet();
        }
        if ([cmd isEqualToString:@"clipboard-set"]) {
            return clipboardSet(textArg);
        }
        if ([cmd isEqualToString:@"request-accessibility"]) {
            NSDictionary *opts = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt:@YES};
            BOOL trusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts);
            emit(@{@"status":@"REQUESTED", @"accessibility":@(trusted)});
            return trusted ? 0 : 2;
        }
        if ([cmd isEqualToString:@"request-screen-recording"]) {
            BOOL granted = CGRequestScreenCaptureAccess();
            emit(@{@"status":granted ? @"PASS" : @"REQUESTED", @"screen_recording":@(granted)});
            return granted ? 0 : 2;
        }
        if ([cmd isEqualToString:@"screen-capture-test"]) {
            return screenCaptureKitCapture(nil, NO);
        }
        if ([cmd isEqualToString:@"screen-capture-file"]) {
            if (imageOutputPath.length == 0) {
                emit(@{@"status":@"FAIL", @"reason":@"missing_image_output"});
                return 64;
            }
            return screenCaptureKitCapture(imageOutputPath, NO);
        }
        if ([cmd isEqualToString:@"screen-ocr"]) {
            return screenCaptureKitCapture(nil, YES);
        }
        if ([cmd isEqualToString:@"automation-finder"]) {
            NSAppleScript *script = [[NSAppleScript alloc] initWithSource:@"tell application \"Finder\" to get name of startup disk"];
            NSDictionary *err = nil;
            NSAppleEventDescriptor *desc = [script executeAndReturnError:&err];
            if (err) {
                emit(@{@"status":@"FAIL", @"error":err.description ?: @"unknown"});
                return 1;
            }
            emit(@{@"status":@"PASS", @"result":desc.stringValue ?: @""});
            return 0;
        }
        if ([cmd isEqualToString:@"automation-systemevents"]) {
            NSAppleScript *script = [[NSAppleScript alloc] initWithSource:@"tell application \"System Events\" to get name of first process whose frontmost is true"];
            NSDictionary *err = nil;
            NSAppleEventDescriptor *desc = [script executeAndReturnError:&err];
            if (err) {
                emit(@{@"status":@"FAIL", @"error":err.description ?: @"unknown"});
                return 1;
            }
            emit(@{@"status":@"PASS", @"frontmost_process":desc.stringValue ?: @""});
            return 0;
        }
        if ([cmd isEqualToString:@"accessibility-test"]) {
            return accessibilityTest();
        }
        if ([cmd isEqualToString:@"accessibility-action-test"]) {
            return accessibilityActionTest();
        }
        if ([cmd isEqualToString:@"accessibility-inventory"]) {
            return accessibilityInventory();
        }
        if ([cmd isEqualToString:@"accessibility-semantic-find"]) {
            return accessibilitySemantic(NO, bundleArg, roleArg, subroleArg, titleArg, descriptionArg, valueArg);
        }
        if ([cmd isEqualToString:@"accessibility-semantic-press"]) {
            return accessibilitySemantic(YES, bundleArg, roleArg, subroleArg, titleArg, descriptionArg, valueArg);
        }
        if ([cmd isEqualToString:@"accessibility-event-observe"]) {
            return accessibilityEventObserve(NO, bundleArg, eventsArg, roleArg, subroleArg, titleArg, descriptionArg, valueArg, observeSecondsArg, eventLimitArg);
        }
        if ([cmd isEqualToString:@"accessibility-event-wait"]) {
            return accessibilityEventObserve(YES, bundleArg, eventsArg, roleArg, subroleArg, titleArg, descriptionArg, valueArg, observeSecondsArg, eventLimitArg);
        }
        if ([cmd isEqualToString:@"frontmost"]) {
            NSRunningApplication *app = NSWorkspace.sharedWorkspace.frontmostApplication;
            emit(@{@"status": app ? @"PASS" : @"FAIL",
                   @"name":app.localizedName ?: @"",
                   @"bundle_id":app.bundleIdentifier ?: @"",
                   @"pid":app ? @(app.processIdentifier) : @0});
            return app ? 0 : 1;
        }
        if ([cmd isEqualToString:@"mouse-position"]) {
            CGEventRef ev = CGEventCreate(NULL);
            CGPoint p = ev ? CGEventGetLocation(ev) : CGPointZero;
            if (ev) CFRelease(ev);
            emit(@{@"status":@"PASS", @"x":@(p.x), @"y":@(p.y)});
            return 0;
        }
        if ([cmd isEqualToString:@"mouse-nudge"]) {
            if (!AXIsProcessTrusted()) {
                emit(@{@"status":@"NEEDS_USER_APPROVAL", @"accessibility":@NO});
                return 2;
            }
            CGEventRef ev = CGEventCreate(NULL);
            CGPoint p = ev ? CGEventGetLocation(ev) : CGPointZero;
            if (ev) CFRelease(ev);
            CGPoint p2 = CGPointMake(p.x + 1.0, p.y);
            CGEventRef m1 = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, p2, kCGMouseButtonLeft);
            CGEventRef m2 = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, p, kCGMouseButtonLeft);
            if (m1) { CGEventPost(kCGHIDEventTap, m1); CFRelease(m1); }
            if (m2) { CGEventPost(kCGHIDEventTap, m2); CFRelease(m2); }
            emit(@{@"status":@"PASS", @"accessibility":@YES, @"restored_x":@(p.x), @"restored_y":@(p.y)});
            return 0;
        }
        if ([cmd isEqualToString:@"type-text"]) {
            if (!textArg) {
                emit(@{@"status":@"FAIL", @"reason":@"missing_text"});
                return 64;
            }
            return guiTypeText(textArg);
        }
        if ([cmd isEqualToString:@"type-text-file"]) {
            return typeTextFile(textFileArg);
        }
        if ([cmd isEqualToString:@"key-press"]) {
            if (keycodeArg < 0 || keycodeArg > 127) {
                emit(@{@"status":@"FAIL", @"reason":@"invalid_keycode"});
                return 64;
            }
            return guiKeyPress((CGKeyCode)keycodeArg, modifiersArg);
        }
        if ([cmd isEqualToString:@"mouse-move"]) {
            if (isnan(xArg) || isnan(yArg)) {
                emit(@{@"status":@"FAIL", @"reason":@"missing_coordinates"});
                return 64;
            }
            return guiMouseMove(xArg, yArg);
        }
        if ([cmd isEqualToString:@"mouse-click"]) {
            if (isnan(xArg) || isnan(yArg)) {
                emit(@{@"status":@"FAIL", @"reason":@"missing_coordinates"});
                return 64;
            }
            return guiMouseClick(xArg, yArg, buttonArg, countArg);
        }
        fprintf(stderr, "unknown command\n");
        return 64;
    }
}
