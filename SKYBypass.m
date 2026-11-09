// SKYBypass.m — SKYCheat.framework runtime bypass + on-screen debug readout
// arm64 / iOS 14+ · clang -dynamiclib -fobjc-arc -framework Foundation -framework UIKit
//
// Why this instead of patching the framework binary:
//   every static attempt died inside the SDK's own show path and we had no way to
//   see *where*.  This dylib drives the SDK's public entry -[ImGuiLoad show] from
//   the main thread on a timer, catches exceptions, and prints each step on screen
//   so the failure is readable without a Mac, Frida or Console.
//
// Offsets are absolute vmaddrs of SKYCheat.framework/SKYCheat (__TEXT vmaddr == 0).

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <objc/message.h>
#import <stdarg.h>
#import <stdint.h>
#import <string.h>

@interface NSObject (SKYBypassShow)
- (void)show;
@end

#define OFF_MENU_OPEN    0x3abc066ULL   // uint8: ImGui p_open of the main window
#define OFF_AUTH_FLAG    0x3aaba60ULL   // uint8: draw gate read by drawInMTKView

static uintptr_t gBase;
static UILabel  *gLabel;
static NSString *gLog;
static id        gImGuiLoad;
static BOOL      gSwizzled;

static NSString *logPath(void)
{
    if (!gLog) {
        NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:docs
                                 withIntermediateDirectories:YES attributes:nil error:NULL];
        gLog = [docs stringByAppendingPathComponent:@"skybypass.log"];
    }
    return gLog;
}

static void LOG(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[SKYBypass] %@", s);
    NSString *line = [NSString stringWithFormat:@"%@\n", s];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath()];
    if (!fh) [[NSFileManager defaultManager] createFileAtPath:logPath() contents:nil attributes:nil];
    fh = [NSFileHandle fileHandleForWritingAtPath:logPath()];
    [fh seekToEndOfFile];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

// on-screen readout: last 4 lines, so a crash point is readable in a screenshot
static NSMutableArray<NSString *> *gLines;
static void STATUS(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    LOG(@"%@", s);
    if (!gLines) gLines = [NSMutableArray array];
    [gLines addObject:s];
    while (gLines.count > 4) [gLines removeObjectAtIndex:0];

    if (!gLabel) {
        UIWindow *w = UIApplication.sharedApplication.windows.firstObject;
        if (!w) return;
        gLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 60, w.bounds.size.width - 16, 90)];
        gLabel.numberOfLines = 4;
        gLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        gLabel.textColor = UIColor.yellowColor;
        gLabel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.65];
        gLabel.userInteractionEnabled = NO;
        [w addSubview:gLabel];
    }
    gLabel.text = [gLines componentsJoinedByString:@"\n"];
}

static uintptr_t base(void)
{
    if (gBase) return gBase;
    for (uint32_t i = 0, n = _dyld_image_count(); i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "SKYCheat.framework")) {
            gBase = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
            return gBase;
        }
    }
    return 0;
}

static void poke(uintptr_t off, uint8_t v)
{
    volatile uint8_t *p = (volatile uint8_t *)(base() + off);
    if (*p != v) *p = v;
}

// ------------------------------------------------------------- ASStatusView

static void swz_none(id s, SEL c) { }
static void swz2(id s, SEL c, id a, id b) { }
static void swz8(id s, SEL c, id a, id b, id d, id e, id f, id g) { }

static void killSel(Class cls, const char *name, IMP imp)
{
    Method m = class_getInstanceMethod(cls, sel_registerName(name));
    if (m) method_setImplementation(m, imp);
}

static void hideLicenseUI(void)
{
    if (gSwizzled) return;
    Class cls = NSClassFromString(@"ASStatusView");
    if (!cls) return;
    gSwizzled = YES;

    killSel(cls, "showWithAnimation", (IMP)swz_none);
    killSel(cls, "updateContentAnimated", (IMP)swz_none);
    killSel(cls, "showLoginForm", (IMP)swz_none);
    killSel(cls, "showExpiredForm", (IMP)swz_none);
    killSel(cls, "showLoginLoading", (IMP)swz_none);
    killSel(cls, "showErrorWithTitle:message:", (IMP)swz2);
    killSel(cls, "showSuccessWithTitle:message:", (IMP)swz2);
    killSel(cls, "showLoadingWithTitle:message:", (IMP)swz2);
    killSel(cls, "showLoginError:", (IMP)swz2);
    killSel(cls, "showLoginFormWithTitle:description:placeholder:submitTitle:contactTitle:countdownFrom:", (IMP)swz8);
    killSel(cls, "showExpiredWithTitle:message:changeKeyTitle:copyUDIDTitle:copyKeyTitle:countdownFrom:", (IMP)swz8);

    for (UIWindow *w in UIApplication.sharedApplication.windows)
        for (UIView *v in w.subviews)
            if ([v isKindOfClass:cls]) v.hidden = YES;
    STATUS(@"license UI swizzled");
}

// ------------------------------------------------------------- overlay

static void tick(void);
static void later(NSTimeInterval s)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(s * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ tick(); });
}

static int gTicks;
static int gShownFails;

static void tick(void)
{
    @try {
        if (!base()) { later(0.5); return; }
        gTicks++;

        hideLicenseUI();
        poke(OFF_AUTH_FLAG, 1);

        NSArray *wins = UIApplication.sharedApplication.windows;
        if (wins.count == 0) { later(1.0); return; }

        UIView *host = [[wins.firstObject rootViewController] view];
        if (!host) { STATUS(@"t%d: no rootVC view", gTicks); later(1.0); return; }

        Class il = NSClassFromString(@"ImGuiLoad");
        if (!il) { STATUS(@"no ImGuiLoad class"); later(2.0); return; }

        if (!gImGuiLoad) {
            gImGuiLoad = [[il alloc] init];
            STATUS(@"t%d: ImGuiLoad %s", gTicks, gImGuiLoad ? "ok" : "nil");
        }
        if (!gImGuiLoad) { later(2.0); return; }

        Class mtk = NSClassFromString(@"MTKView");
        BOOL attached = NO;
        for (UIView *v in host.subviews)
            if (mtk && [v isKindOfClass:mtk]) attached = YES;

        if (!attached && gShownFails < 3) {
            @try {
                [(NSObject *)gImGuiLoad performSelector:NSSelectorFromString(@"show")];
                STATUS(@"t%d: show() ok, host=%@", gTicks, NSStringFromClass([host class]));
            } @catch (NSException *e) {
                gShownFails++;
                STATUS(@"t%d: show EXC %@", gTicks, e.reason);
            }
            for (UIView *v in host.subviews)
                if (mtk && [v isKindOfClass:mtk]) attached = YES;
            STATUS(@"t%d: MTKView %@", gTicks, attached ? @"ATTACHED" : @"missing");
        } else if (attached && gTicks % 15 == 1) {
            STATUS(@"t%d: overlay alive (mtkView in window)", gTicks);
        }

        if (attached && gLabel && !gLabel.superview) [host addSubview:gLabel];

        poke(OFF_MENU_OPEN, 1);

        if (gTicks < 600) later(2.0);
    } @catch (NSException *e) {
        STATUS(@"tick EXC %@", e.reason);
        later(2.0);
    }
}

__attribute__((constructor))
static void skyInit(void)
{
    LOG(@"---- SKYBypass loaded ----");
    NSSetUncaughtExceptionHandler(NULL);
    dispatch_async(dispatch_get_main_queue(), ^{
        STATUS(@"SKYBypass loaded, waiting for SKYCheat");
        later(2.0);
    });
}
