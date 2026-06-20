"use strict";

// OEP-finding logic ported from ergrelet/unlicense (GPL-3.0) resources/frida.js. The transport is
// changed from Frida's rpc.exports/send (which the Rust frida binding does not deliver) to a local
// socket: the agent connects to DRIVER_PORT, serves driver requests, and pushes the oep_reached
// event. DRIVER_PORT is prepended by the driver before the script is created.

const green = "\x1b[1;36m";
const reset = "\x1b[0m";

let allocatedBuffers = [];
let originalPageProtections = new Map();
let oepTracingListeners = [];
let oepReached = false;

let skipDllOepInstr32 = null;
let skipDllOepInstr64 = null;
let dllOepCandidate = null;

let skipTlsInstr32 = null;
let skipTlsInstr64 = null;
let tlsCallbackCount = 0;

// OEP report, filled by notifyOepFound and pushed over the socket by the serve loop.
let oepReport = null;

let logQueue = [];
function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
    logQueue.push(String(message));
}

// Compatibility shims: Frida 17 removed the legacy static Module.findExportByName(mod, name) and the
// *Sync range enumerators, so probe for the available form at runtime.
function modByName(name) {
    if (typeof Process.findModuleByName === 'function') { const m = Process.findModuleByName(name); if (m) return m; }
    if (typeof Process.getModuleByName === 'function') { try { const m = Process.getModuleByName(name); if (m) return m; } catch (e) { } }
    const lower = name.toLowerCase();
    const all = Process.enumerateModules();
    for (let i = 0; i < all.length; i++) { if (all[i].name.toLowerCase() === lower) return all[i]; }
    return null;
}
function findExport(moduleName, exportName) {
    const m = modByName(moduleName);
    if (m && typeof m.findExportByName === 'function') return m.findExportByName(exportName);
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(exportName);
    if (typeof Module.findExportByName === 'function') return Module.findExportByName(moduleName, exportName);
    return null;
}
function enumRanges(prot) {
    if (typeof Process.enumerateRanges === 'function') return Process.enumerateRanges(prot);
    if (typeof Process.enumerateRangesSync === 'function') return Process.enumerateRangesSync(prot);
    return [];
}
function rangeAt(address) {
    if (typeof Process.findRangeByAddress === 'function') return Process.findRangeByAddress(address);
    if (typeof Process.getRangeByAddress === 'function') { try { return Process.getRangeByAddress(address); } catch (e) { return null; } }
    return null;
}

function initializeTrampolines() {
    const instructionsBytes = new Uint8Array([
        0xC3,
        0xC2, 0x0C, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00
    ]);
    let bufferPointer = Memory.alloc(instructionsBytes.length);
    Memory.protect(bufferPointer, instructionsBytes.length, 'rwx');
    bufferPointer.writeByteArray(instructionsBytes.buffer);
    skipTlsInstr64 = bufferPointer;
    skipTlsInstr32 = bufferPointer.add(0x1);
    skipDllOepInstr64 = bufferPointer.add(0x4);
    skipDllOepInstr32 = bufferPointer.add(0xA);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function notifyOepFound(dumpedModule, oepCandidate) {
    oepReached = true;
    setOepRangesProtection('rw-');
    removeOepTracingHooks();
    let isDotNetInitialized = isDotNetProcess();
    oepReport = { OEP: oepCandidate.toString(), BASE: dumpedModule.base.toString(), DOTNET: isDotNetInitialized };
    // Freeze this thread at the OEP. recv().wait() releases the JS lock so the socket serve loop
    // keeps running; the driver never sends 'block_on_oep', so this blocks until the process is killed.
    let sync_op = recv('block_on_oep', function (_value) { });
    sync_op.wait();
}

function isDotNetProcess() {
    return modByName("clr.dll") != null;
}

function makeOepRangesInaccessible(dumpedModule, expectedOepRanges) {
    expectedOepRanges.forEach((oepRange) => {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const expectedSectionSize = oepRange[1];
        Memory.protect(sectionStart, expectedSectionSize, '---');
        originalPageProtections.set(sectionStart.toString(), expectedSectionSize);
    });
}

function setOepRangesProtection(protection) {
    originalPageProtections.forEach((size, address_str, _map) => {
        Memory.protect(ptr(address_str), size, protection);
    });
}

function removeOepTracingHooks() {
    oepTracingListeners.forEach(listener => { listener.detach(); });
    oepTracingListeners = [];
}

function registerExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    Process.setExceptionHandler(exp => {
        let oepCandidate = exp.context.pc;
        let threadId = Process.getCurrentThreadId();
        if (exp.memory != null) {
            if (exp.memory.operation == "read" && exp.memory.address.equals(exp.context.pc)) {
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;
                    skipTlsCallback(exp.context);
                    return true;
                }
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                notifyOepFound(dumpedModule, oepCandidate);
            }
            if (exp.memory.operation != "execute") {
                Memory.protect(exp.memory.address, Process.pageSize, "rw-");
                return true;
            }
        }
        let expectionHandled = false;
        expectedOepRanges.forEach((oepRange) => {
            const sectionStart = dumpedModule.base.add(oepRange[0]);
            const sectionSize = oepRange[1];
            const sectionRange = { base: sectionStart, size: sectionSize };
            if (rangeContainsAddress(sectionRange, oepCandidate)) {
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;
                    skipTlsCallback(exp.context);
                    expectionHandled = true;
                    return;
                }
                if (moduleIsDll) {
                    if (!oepReached) {
                        log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                        dllOepCandidate = oepCandidate;
                    }
                    skipDllEntryPoint(exp.context);
                    expectionHandled = true;
                    return;
                }
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                notifyOepFound(dumpedModule, oepCandidate);
            }
        });
        return expectionHandled;
    });
    log("Exception handler registered");
}

function isTlsCallback(exceptionCtx, dumpedModule) {
    if (Process.arch == "x64") {
        let moduleBase = exceptionCtx.rcx;
        if (!moduleBase.equals(dumpedModule.base)) { return false; }
        let reason = exceptionCtx.rdx;
        if (reason.compare(ptr(4)) > 0) { return false; }
    } else if (Process.arch == "ia32") {
        let sp = exceptionCtx.sp;
        let moduleBase = sp.add(0x4).readPointer();
        if (!moduleBase.equals(dumpedModule.base)) { return false; }
        let reason = sp.add(0x8).readPointer();
        if (reason.compare(ptr(4)) > 0) { return false; }
    } else {
        return false;
    }
    return true;
}

function skipTlsCallback(exceptionCtx) {
    if (Process.arch == "x64") { exceptionCtx.rip = skipTlsInstr64; }
    else if (Process.arch == "ia32") { exceptionCtx.eip = skipTlsInstr32; }
}

function skipDllEntryPoint(exceptionCtx) {
    if (Process.arch == "x64") { exceptionCtx.rip = skipDllOepInstr64; }
    else if (Process.arch == "ia32") { exceptionCtx.eip = skipDllOepInstr32; }
}

function setupOepTracing(moduleName, expectedOepRanges) {
    log(`Setting up OEP tracing for "${moduleName}"`);
    let targetIsDll = moduleName.endsWith(".dll");
    let dumpedModule = null;
    initializeTrampolines();
    if (!targetIsDll) { dumpedModule = modByName(moduleName); }

    const loadDll = findExport('ntdll', 'LdrLoadDll');
    const loadDllListener = Interceptor.attach(loadDll, {
        onLeave: function (_args) {
            if (dllOepCandidate != null && !oepReached) {
                notifyOepFound(dumpedModule, dllOepCandidate);
            }
        }
    });
    oepTracingListeners.push(loadDllListener);

    let exceptionHandlerRegistered = false;
    const ntProtectVirtualMemory = findExport('ntdll', 'NtProtectVirtualMemory');
    if (ntProtectVirtualMemory != null) {
        const ntProtectVirtualMemoryListener = Interceptor.attach(ntProtectVirtualMemory, {
            onEnter: function (args) {
                let addr = args[1].readPointer();
                if (dumpedModule != null && addr.equals(dumpedModule.base)) {
                    makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                    if (!exceptionHandlerRegistered) {
                        registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                        exceptionHandlerRegistered = true;
                    }
                }
            }
        });
        oepTracingListeners.push(ntProtectVirtualMemoryListener);
    }

    let initializeFusionHooked = false;
    const activateActivationContext = findExport('ntdll', 'RtlActivateActivationContextUnsafeFast');
    const activateActivationContextListener = Interceptor.attach(activateActivationContext, {
        onLeave: function (_args) {
            if (dumpedModule == null) {
                dumpedModule = modByName(moduleName);
                if (dumpedModule == null) { return; }
                log(`Target module has been loaded (thread #${this.threadId}) ...`);
            }
            if (targetIsDll) {
                if (!exceptionHandlerRegistered) {
                    makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                    registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                    exceptionHandlerRegistered = true;
                }
            }
            const initializeFusion = findExport('clr', 'InitializeFusion');
            if (initializeFusion != null && !initializeFusionHooked) {
                const initializeFusionListener = Interceptor.attach(initializeFusion, {
                    onEnter: function (_args) {
                        log(`.NET assembly loaded (thread #${this.threadId})`);
                        notifyOepFound(dumpedModule, ptr('0'));
                    }
                });
                oepTracingListeners.push(initializeFusionListener);
                initializeFusionHooked = true;
            }
        }
    });
    oepTracingListeners.push(activateActivationContextListener);
}

// Driver request dispatch. Returns { value, bin } where bin is an ArrayBuffer for memory reads.
function dispatch(method, args) {
    switch (method) {
        case "getArchitecture": return { value: Process.arch, bin: null };
        case "getPointerSize": return { value: Process.pointerSize, bin: null };
        case "getPageSize": return { value: Process.pageSize, bin: null };
        case "setupOepTracing":
            setupOepTracing(args[0], args[1]);
            return { value: null, bin: null };
        case "notifyDumpingFinished":
            setOepRangesProtection('rwx');
            return { value: null, bin: null };
        case "pollOep": {
            const logs = logQueue.splice(0, logQueue.length);
            return { value: { oep: oepReport, logs: logs }, bin: null };
        }
        case "findModuleByAddress": {
            const m = Process.findModuleByAddress(ptr(args[0]));
            return { value: m == null ? null : { name: m.name, base: m.base.toString(), size: m.size, path: m.path }, bin: null };
        }
        case "findRangeByAddress": {
            const r = rangeAt(ptr(args[0]));
            return { value: r == null ? null : { base: r.base.toString(), size: r.size, protection: r.protection }, bin: null };
        }
        case "findExportByName": {
            const a = findExport(args[0], args[1]);
            return { value: a == null ? null : a.toString(), bin: null };
        }
        case "enumerateModules":
            return { value: Process.enumerateModules().map(m => m.name), bin: null };
        case "enumerateModuleRanges": {
            const wanted = args[0].toUpperCase();
            const ranges = enumRanges("r--").filter(range => {
                const module = Process.findModuleByAddress(range.base);
                return module != null && module.name.toUpperCase() == wanted;
            });
            return { value: ranges.map(r => ({ base: r.base.toString(), size: r.size, protection: r.protection })), bin: null };
        }
        case "enumerateExportedFunctions": {
            const excluded = args[0];
            const out = [];
            Process.enumerateModules().forEach(m => {
                if (m.name != excluded) {
                    m.enumerateExports().forEach(e => {
                        if (e.type == "function" && e.hasOwnProperty('address')) {
                            out.push({ name: e.name, address: e.address.toString() });
                        }
                    });
                }
            });
            return { value: out, bin: null };
        }
        case "allocateProcessMemory": {
            const size = args[0];
            const near = args[1];
            const sizeRounded = size + (Process.pageSize - size % Process.pageSize);
            const addr = Memory.alloc(sizeRounded, { near: ptr(near), maxDistance: 0xff000000 });
            allocatedBuffers.push(addr);
            return { value: addr.toString(), bin: null };
        }
        case "queryMemoryProtection": {
            const r = rangeAt(ptr(args[0]));
            if (r == null) { throw new Error("no range at address"); }
            return { value: r.protection, bin: null };
        }
        case "setMemoryProtection":
            return { value: Memory.protect(ptr(args[0]), args[1], args[2]), bin: null };
        case "readProcessMemory": {
            const buf = ptr(args[0]).readByteArray(args[1]);
            return { value: null, bin: buf };
        }
        case "writeProcessMemory":
            ptr(args[0]).writeByteArray(args[1]);
            return { value: null, bin: null };
        default:
            throw new Error("unknown method: " + method);
    }
}

// ---- Socket transport ----

function u8FromStr(s) {
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i) & 0xff; }
    return out;
}
function strFromU8(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++) { s += String.fromCharCode(u8[i]); }
    return s;
}

async function readFrame(input) {
    const lenBuf = await input.readAll(4);
    const len = new DataView(lenBuf).getUint32(0, true);
    const payload = await input.readAll(len);
    return new Uint8Array(payload);
}
async function writeJson(output, obj) {
    const body = u8FromStr(JSON.stringify(obj));
    const frame = new Uint8Array(5 + body.length);
    new DataView(frame.buffer).setUint32(0, 1 + body.length, true);
    frame[4] = 0x4A; // 'J'
    frame.set(body, 5);
    await output.writeAll(frame.buffer);
}
async function writeBin(output, arrbuf) {
    const data = new Uint8Array(arrbuf);
    const frame = new Uint8Array(5 + data.length);
    new DataView(frame.buffer).setUint32(0, 1 + data.length, true);
    frame[4] = 0x42; // 'B'
    frame.set(data, 5);
    await output.writeAll(frame.buffer);
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function serve() {
    const conn = await Socket.connect({ family: 'ipv4', host: '127.0.0.1', port: DRIVER_PORT });
    conn.setNoDelay(true);
    const input = conn.input;
    const output = conn.output;
    log(`connected to driver on 127.0.0.1:${DRIVER_PORT}`);

    // No async watcher: the driver polls pollOep over this serve loop, which is robust across Frida
    // JS-runtime versions (a setTimeout-based poller here was not).
    while (true) {
        const frame = await readFrame(input);
        const req = JSON.parse(strFromU8(frame.subarray(1)));
        try {
            const res = dispatch(req.method, req.args);
            if (res.bin != null) {
                await writeJson(output, { id: req.id, ok: true, bin: true });
                await writeBin(output, res.bin);
            } else {
                await writeJson(output, { id: req.id, ok: true, value: res.value === undefined ? null : res.value });
            }
        } catch (e) {
            const stack = (e && e.stack) ? String(e.stack).split("\n").join(" | ") : "";
            await writeJson(output, { id: req.id, ok: false, error: String(e) + " @ " + stack });
        }
    }
}

serve().catch(e => log("serve error: " + e));
