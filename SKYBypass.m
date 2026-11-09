// SKYBypass.m — SKYCheat.framework runtime bypass (v2)
//   · v1 worked: the menu appeared.  v2 fixes the two problems v1 had:
//       - the menu could never be closed  -> we stopped poking menu_open every tick
//       - the app crashed                 -> show()/hide() are now called at most twice,
//                                            never again once the overlay is attached
//   · adds its own 3-finger double-tap toggle (same gesture as the cheat) so the menu
//     can be closed without depending on the SDK's own recogniser.
//
// arm64 / iOS 14+ · clang -dynamiclib -fobjc-arc -framework Foundation -framework UIKit

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <execinfo.h>
#import <signal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#import <sys/ucontext.h>
#import <unistd.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdint.h>
#import <string.h>

#define OFF_MENU_OPEN    0x3abc066ULL   // uint8: ImGui p_open of the main window
#define OFF_AUTH_FLAG    0x3aaba60ULL   // uint8: draw gate read by drawInMTKView
#define MAX_SHOWS        2

// the yellow text in the corner is my debug readout, not the cheat's UI.
//   1 = show it for a few seconds while starting  ·  0 = never show it
#define SHOW_DEBUG_LABEL 1
#define LABEL_LIFETIME   5.0

// v4 diagnostic switch:
//   1 = keep the overlay attached but force menu_open back to 0, so ImGui never
//       draws the menu, and nothing inside it can run.  stays alive => the crash is
//       in the menu/draw side;  still crashes => the crash is in attaching the view.
#define DIAG_NO_DRAW     0
#define TICK_SECONDS     2.0
#define WATCHDOG_SECONDS 20.0

static uintptr_t gBase;
static uintptr_t base(void);
static NSString *gLog;
static id        gImGuiLoad;
static BOOL      gSwizzled;
static BOOL      gAttached;
static BOOL      gWatchdogRunning;
static int       gShows;
static int       gTicks;
static int       gPatched;

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
    if (![NSFileManager.defaultManager fileExistsAtPath:logPath()])
        [NSFileManager.defaultManager createFileAtPath:logPath() contents:nil attributes:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath()];
    [fh seekToEndOfFile];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

// ------------------------------------------------- crash capture
// A crash dies before we can read anything, so: on SIGSEGV/SIGABRT/etc we dump the
// backtrace to Documents/skycrash.log, and on the NEXT launch that file is copied to
// the pasteboard -- paste it in chat and the crashing frame is readable offline.

static NSString *crashPath(void)
{
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
                             withIntermediateDirectories:YES attributes:nil error:NULL];
    return [docs stringByAppendingPathComponent:@"skycrash.log"];
}

static void skySignal(int sig, siginfo_t *si, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    uintptr_t pc = 0, lr = 0, fpx = 0, r0 = 0, r1 = 0;
    if (uc && uc->uc_mcontext) {
        pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
        lr = (uintptr_t)uc->uc_mcontext->__ss.__lr;
        fpx = (uintptr_t)uc->uc_mcontext->__ss.__fp;
        r0 = (uintptr_t)uc->uc_mcontext->__ss.__x[0];
        r1 = (uintptr_t)uc->uc_mcontext->__ss.__x[1];
    }
    void *frames[48];
    int n = backtrace(frames, 48);
    char buf[8192];
    int len = 0;
    len += snprintf(buf + len, sizeof(buf) - len, "signal %d (%s)\n", sig, strsignal(sig));
    len += snprintf(buf + len, sizeof(buf) - len,"fault=%p pc=0x%lx lr=0x%lx fp=0x%lx x0=0x%lx x1=0x%lx\n",(void *)(si ? si->si_addr : 0), (unsigned long)pc, (unsigned long)lr,(unsigned long)fpx, (unsigned long)r0, (unsigned long)r1);
    {
        Dl_info pi; const char *img = "?";
        unsigned long off = 0;
        if (pc && dladdr((void *)pc, &pi) && pi.dli_fbase) {
            off = (unsigned long)(pc - (uintptr_t)pi.dli_fbase);
            if (pi.dli_fname) { const char *sl = strrchr(pi.dli_fname, '/'); img = sl ? sl + 1 : pi.dli_fname; }
        }
        len += snprintf(buf + len, sizeof(buf) - len, "pcimg=%s+0x%lx", img, off);
        img = "?"; off = 0;
        if (lr && dladdr((void *)lr, &pi) && pi.dli_fbase) {
            off = (unsigned long)(lr - (uintptr_t)pi.dli_fbase);
            if (pi.dli_fname) { const char *sl = strrchr(pi.dli_fname, '/'); img = sl ? sl + 1 : pi.dli_fname; }
        }
        len += snprintf(buf + len, sizeof(buf) - len, " lrimg=%s+0x%lx (slide inside SKYCheat base 0x%lx)\n",
                        img, off, (unsigned long)base());
    }
    for (int i = 0; i < n && len < (int)sizeof(buf) - 200; i++) {
        Dl_info info;
        uintptr_t off = 0;
        const char *img = "?";
        if (dladdr(frames[i], &info) && info.dli_fbase) {
            off = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
            if (info.dli_fname) {
                const char *slash = strrchr(info.dli_fname, '/');
                img = slash ? slash + 1 : info.dli_fname;
            }
        }
        len += snprintf(buf + len, sizeof(buf) - len, "#%02d %s+0x%lx %s\n",
                        i, img, (unsigned long)off, (info.dli_sname ? info.dli_sname : ""));
    }
    int fd = open([crashPath() fileSystemRepresentation], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { write(fd, buf, len); close(fd); }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void armCrashHandlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = skySignal;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP };
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) sigaction(sigs[i], &sa, NULL);
}

// runtime code patch inside SKYCheat (COW page + icache flush)
static int patchCode(uintptr_t addr, uint32_t word)
{
    vm_address_t page = (vm_address_t)(addr & ~(uintptr_t)0x3fff);
    if (vm_protect(mach_task_self(), page, 0x4000, false,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) return 0;
    *(volatile uint32_t *)addr = word;
    sys_icache_invalidate((void *)addr, 4);
    vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
    return 1;
}

// 0x2f293a8: the per-frame routine invoked by drawInMTKView does an indirect call to a
// global callback with a NULL context -> SIGSEGV (that is exactly what the crash log
// shows). Replace `blr x8` with `mov w0, #0` so the callback is skipped and the code
// takes its "no callback" branch instead.
#define OFF_FRAME_CB   0x2f293a8ULL
#define PATCH_FRAME_CB 1

static void publishCrashReport(void)
{
    if (![[NSFileManager defaultManager] fileExistsAtPath:crashPath()]) return;
    NSString *txt = [NSString stringWithContentsOfFile:crashPath() encoding:NSUTF8StringEncoding error:NULL];
    if (txt.length) {
        [UIPasteboard generalPasteboard].string = txt;
        LOG(@"crash report from last run copied to pasteboard");
    }
    [[NSFileManager defaultManager] removeItemAtPath:crashPath() error:NULL];
}

// ------------------------------------------------- on-screen status (debug)

static UILabel *gLabel;
static NSMutableArray<NSString *> *gLines;

static void STATUS(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s2 = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    LOG(@"%@", s2);

    if (!gLines) gLines = [NSMutableArray array];
    [gLines addObject:s2];
    while (gLines.count > 4) [gLines removeObjectAtIndex:0];

#if !SHOW_DEBUG_LABEL
    return;
#endif
    if (!gLabel) {
        UIWindow *w = UIApplication.sharedApplication.windows.firstObject;
        if (!w) return;
        gLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 60, w.bounds.size.width - 16, 84)];
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

static uint8_t peek(uintptr_t off) { return *(volatile uint8_t *)(base() + off); }

// ------------------------------------------------------------ licence UI

// NOTE: parameters are declared as plain integers, not objects, on purpose.
// With `id` params the compiler under ARC emitted objc_storeStrong on garbage argv
// slots and that itself crashed (see skycrash.log: swz8 -> objc_storeStrong -> SIGSEGV).
static void swz_none(id s, SEL c) { }
static void swz2(id s, SEL c, uintptr_t a, uintptr_t b) { }
static void swz8(id s, SEL c, uintptr_t a, uintptr_t b, uintptr_t d,
                 uintptr_t e, uintptr_t f, uintptr_t g) { }

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
    LOG(@"license UI swizzled");
}

// ------------------------------------------------------------ overlay

static UIView *hostView(void)
{
    UIWindow *w = UIApplication.sharedApplication.windows.firstObject;
    return w.rootViewController.view;
}

static BOOL overlayAttached(void)
{
    Class mtk = NSClassFromString(@"MTKView");
    UIView *host = hostView();
    if (!mtk || !host) return NO;
    for (UIView *v in host.subviews)
        if ([v isKindOfClass:mtk]) return YES;
    return NO;
}

static id imguiload(void)
{
    if (gImGuiLoad) return gImGuiLoad;
    Class il = NSClassFromString(@"ImGuiLoad");
    if (!il) return nil;
    gImGuiLoad = [[il alloc] init];
    LOG(@"ImGuiLoad instance %@", gImGuiLoad ? @"created" : @"nil");
    return gImGuiLoad;
}

static void skyShowMenu(void)
{
    id il = imguiload();
    if (!il || gShows >= MAX_SHOWS) return;
    gShows++;
    @try {
        [(NSObject *)il performSelector:NSSelectorFromString(@"show")];
        STATUS(@"show #%d", gShows);
    } @catch (NSException *e) {
        STATUS(@"show EXC %@", e.reason);
    }
}

static void skyHideMenu(void)
{
    id il = imguiload();
    if (!il) return;
    @try {
        [(NSObject *)il performSelector:NSSelectorFromString(@"hide")];
        LOG(@"hide()");
    } @catch (NSException *e) {
        LOG(@"hide EXC %@", e.reason);
    }
}

// ------------------------------------------------------------ loop

static void tick(void);
static void later(NSTimeInterval s)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(s * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ tick(); });
}

static void tick(void)
{
    @try {
        if (!base()) { later(0.5); return; }
        gTicks++;

        hideLicenseUI();

#if PATCH_FRAME_CB
        if (!gPatched) {
            gPatched = 1;
            int ok = patchCode(base() + OFF_FRAME_CB, 0x52800000u);
            STATUS(@"patch frame-cb %@", ok ? @"ok" : @"FAILED");
        }
#endif

        if (!UIApplication.sharedApplication.windows.count) { later(TICK_SECONDS); return; }
        if (!hostView()) { later(TICK_SECONDS); return; }

        gAttached = overlayAttached();

        if (!gAttached) {
            if (gShows < MAX_SHOWS) skyShowMenu();
            gAttached = overlayAttached();
            if (gAttached) {
                STATUS(@"ATTACHED t%d", gTicks);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(LABEL_LIFETIME * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    [gLabel removeFromSuperview];
                    gLabel = nil;
                });
                // from now on we never poke menu_open again: the gesture must be able
                // to close the menu, and the SDK owns that byte.
                *(volatile uint8_t *)(base() + OFF_AUTH_FLAG) = 1;
#if DIAG_NO_DRAW
                *(volatile uint8_t *)(base() + OFF_MENU_OPEN) = 0;
                STATUS(@"DIAG: menu pinned CLOSED");
#endif
            }
        }

        if (gAttached && !gWatchdogRunning) {
            gWatchdogRunning = YES;
            STATUS(@"watchdog armed");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(WATCHDOG_SECONDS * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if (!overlayAttached()) {
                    STATUS(@"watchdog: overlay gone, re-show");
                    gAttached = NO;
                    skyShowMenu();
                }
            });
        }

        if (!gAttached && gTicks < 120) later(TICK_SECONDS);
    } @catch (NSException *e) {
        LOG(@"tick EXC %@", e.reason);
        later(TICK_SECONDS);
    }
}

__attribute__((constructor))
static void skyInit(void)
{
    armCrashHandlers();
    publishCrashReport();
    STATUS(@"SKYBypass v7 diag=%d patched=%d", DIAG_NO_DRAW, PATCH_FRAME_CB);
    dispatch_async(dispatch_get_main_queue(), ^{ later(2.0); });
}
