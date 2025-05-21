#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import signal
import sys

import frida

"""
Frida BB tracer that outputs in DRcov format.

Frida script is responsible for:
- Getting and sending the process module map initially
- Getting the code execution events
- Parsing the raw event into a GumCompileEvent
- Converting from GumCompileEvent to DRcov block
- Sending a list of DRcov blocks to python

Python side is responsible for:
- Attaching and detaching from the target process
- Removing duplicate DRcov blocks
- Formatting module map and blocks
- Writing the output file
"""

# our frida script, takes two string arguments to embed
# 1. whitelist of modules, in the form "['module_a', 'module_b']" or "['all']"
# 2. threads to trace, in the form "[345, 765]" or "['all']"
js = """
"use strict";

var whitelist = %s;
var threadlist = %s;

// get the module map
// This function prepares module data for internal JS use (with NativePointers)
// and also creates a version for sending to Python (with stringified addresses and explicit id/end)
function prepare_module_data() {
    var raw_modules = Process.enumerateModules();
    var internal_use_modules = [];
    var python_send_modules = [];

    for (var i = 0; i < raw_modules.length; i++) {
        var mod = raw_modules[i];
        var mod_end = mod.base.add(mod.size); // Calculate end address as NativePointer

        // For internal JavaScript use (e.g., module_ids map)
        internal_use_modules.push({
            id: i,
            name: mod.name,
            base: mod.base, // NativePointer
            size: mod.size,
            path: mod.path,
            end: mod_end    // NativePointer
        });

        // For sending to Python (plain objects with stringified addresses)
        python_send_modules.push({
            id: i,
            name: mod.name,
            base: mod.base.toString(), // Stringified
            size: mod.size,
            path: mod.path,
            end: mod_end.toString()    // Stringified
        });
    }
    return { internal: internal_use_modules, for_python: python_send_modules };
}

var module_data = prepare_module_data();
var maps_for_js = module_data.internal;      // Use this for JS logic needing NativePointers
var maps_for_python = module_data.for_python; // Send this to Python

send({'map': maps_for_python}); // Send the version with stringified addresses and explicit id/end

// Populate module_ids using maps_for_js to keep NativePointer for 'start'
var module_ids = {};
maps_for_js.forEach(function (e) {
    module_ids[e.path] = {id: e.id, start: e.base}; // e.base is NativePointer
});

var filtered_maps = new ModuleMap(function (m) {
    // m is a Module object from Frida with original properties (name, base as NativePointer, etc.)
    if (whitelist.indexOf('all') >= 0) { return true; }
    return whitelist.some(item => m.name.toLowerCase().includes(item.toLowerCase()));
});

// this function takes a list of GumCompileEvents and converts it into a DRcov
// entry. Note that we'll get duplicated events when two traced threads
// execute the same code, but this will be handled by the python side.
function drcov_bbs(bbs, fmaps, path_ids) {
    var entry_sz = 8; // size of bb_entry_t in bytes (4 + 2 + 2)
    var buffer = new ArrayBuffer(entry_sz * bbs.length);
    var view = new DataView(buffer);
    var num_entries = 0;

    for (var i = 0; i < bbs.length; ++i) {
        var e = bbs[i];
        var start_addr = e[0]; // NativePointer
        var end_addr = e[1];   // NativePointer

        var path = fmaps.findPath(start_addr);
        if (path === null) { continue; }

        var mod_info = path_ids[path];
        if (!mod_info || !(mod_info.start instanceof NativePointer)) {
             // console.warn("Module info not found or mod_info.start is not a NativePointer for path: " + path);
             continue;
        }

        var offset = start_addr.sub(mod_info.start).toInt32();
        var size = end_addr.sub(start_addr).toInt32();
        var mod_id = mod_info.id;

        view.setUint32(num_entries * entry_sz, offset, true);     // offset
        view.setUint16(num_entries * entry_sz + 4, size, true);   // size
        view.setUint16(num_entries * entry_sz + 6, mod_id, true); // mod_id
        ++num_entries;
    }

    if (num_entries === 0) {
        return null;
    }
    return new Uint8Array(buffer, 0, num_entries * entry_sz);
}

Stalker.trustThreshold = 0;

console.log('Starting to stalk threads...');
Process.enumerateThreads({
    onMatch: function (thread) {
        if (threadlist.indexOf(thread.id) < 0 && threadlist.indexOf('all') < 0) {
            return;
        }
        console.log('Stalking thread ' + thread.id + '.');
        Stalker.follow(thread.id, {
            events: { compile: true },
            onReceive: function (events) {
                var parsed_bbs = Stalker.parse(events, {stringify: false, annotate: false});
                if (parsed_bbs && parsed_bbs.length > 0) {
                    var bbs_data = drcov_bbs(parsed_bbs, filtered_maps, module_ids);
                    if (bbs_data && bbs_data.buffer.byteLength > 0) {
                        send({bbs: 1}, bbs_data);
                    }
                }
            }
        });
    },
    onComplete: function () { console.log('Done enumerating threads for stalking.'); }
});
"""

# these are global so we can easily access them from the frida callbacks or
# signal handlers. It's important that bbs is a set, as we're going to depend
# on it's uniquing behavior for deduplication
modules = []
bbs = set([])  # Using a set to store bytes objects of BBs for automatic deduplication
outfile = "frida-cov.log"


# this converts the object frida sends which has string addresses into
# a python dict
def populate_modules(image_list):
    global modules
    modules = []  # Clear previous modules if any (e.g., re-attach scenario)
    for image in image_list:
        try:
            # Expect 'id', 'base', 'end', 'size', 'name', 'path'
            idx = image["id"]  # This should now exist
            path = image["path"]
            base = int(str(image["base"]), 0)  # JS sends base as string
            end = int(str(image["end"]), 0)  # JS sends end as string
            size = int(image["size"])

            m = {
                "id": idx,
                "path": path,
                "base": base,
                "end": end,
                "size": size,
                "name": image["name"],
            }
            modules.append(m)
        except KeyError as e:
            print(
                f"[-] Error processing module (KeyError: {e}): {image}. This might indicate a mismatch in expected fields."
            )
            continue
        except Exception as e:
            print(f"[-] Error processing module: {image}. Error: {e}")
            continue

    # Sort modules by ID for consistent output, though DRcov doesn't strictly require it
    modules.sort(key=lambda m: m["id"])
    print(f"[+] Got module info for {len(modules)} modules.")


# called when we get coverage data from frida
def populate_bbs(data):
    global bbs
    if data is None or len(data) == 0:
        return

    block_sz = 8
    if len(data) % block_sz != 0:
        print(
            f"[-] Warning: Received BB data of length {len(data)}, which is not a multiple of {block_sz}. Skipping this batch."
        )
        return

    for i in range(0, len(data), block_sz):
        bbs.add(data[i : i + block_sz])


# take the module dict and format it as a drcov logfile header
def create_header(mods):
    header = ""
    header += "DRCOV VERSION: 2\n"
    header += "DRCOV FLAVOR: frida\n"
    if not mods:
        print("[-] Warning: No modules found to create header.")
        header += "Module Table: version 2, count 0\n"
        header += "Columns: id, base, end, entry, checksum, timestamp, path\n"
        return header.encode("utf-8")

    header += "Module Table: version 2, count %d\n" % len(mods)
    header += "Columns: id, base, end, entry, checksum, timestamp, path\n"

    entries = []
    for m in mods:
        entry = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
            m["id"],
            m["base"],
            m["end"],
            0,  # entry
            0,  # checksum
            0,  # timestamp
            m["path"],
        )
        entries.append(entry)

    header_modules = "\n".join(entries)
    return ("%s%s\n" % (header, header_modules)).encode("utf-8")


# take the recv'd basic blocks, finish the header, and append the coverage
def create_coverage(data_set):
    sorted_data = sorted(list(data_set))
    bb_header = b"BB Table: %d bbs\n" % len(sorted_data)
    return bb_header + b"".join(sorted_data)


def on_message(msg, data):
    if msg["type"] == "error":
        print(f"[!] Frida script error: {msg.get('description', 'No description')}")
        if "stack" in msg:
            print(msg["stack"])
        return

    if msg["type"] == "send":
        payload = msg.get("payload", {})
        if "map" in payload:
            maps_data = payload["map"]
            if maps_data:
                populate_modules(maps_data)
            else:
                print("[-] Received empty module map.")
        elif "bbs" in payload:
            if data:
                populate_bbs(data)


def sigint_handler(signo, frame):
    print(f"\n[!] Received signal {signo}, preparing to save coverage...")
    save_coverage()
    print(f"[!] Coverage saved. Exiting due to signal {signo}.")
    os._exit(1)


def save_coverage():
    global modules, bbs, outfile
    if not modules:
        print("[-] No module information collected. Output file might be incomplete.")
    if not bbs:
        print("[-] No basic blocks collected.")

    print(f"[*] Saving {len(bbs)} unique blocks to '{outfile}'")

    try:
        header = create_header(modules)
        body = create_coverage(bbs)

        with open(outfile, "wb") as h:
            h.write(header)
            h.write(body)
        print(f"[+] Coverage data successfully written to {outfile}.")
    except Exception as e:
        print(f"[!] Error saving coverage data: {e}")


def main():
    global outfile

    parser = argparse.ArgumentParser(
        description="Frida-based basic block tracer (DRcov format)"
    )
    parser.add_argument("target", help="Target process name or PID")
    parser.add_argument(
        "-o", "--outfile", help="Output coverage file name", default="frida-cov.log"
    )
    parser.add_argument(
        "-w",
        "--whitelist-modules",
        help="Module name (or part of it) to trace. Can be specified multiple times. Default: ['all']",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-t",
        "--thread-id",
        help="Thread ID to trace. Can be specified multiple times. Default: ['all'] to trace all threads.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-D",
        "--device",
        help="Select a device by ID (e.g., 'usb', 'local', 'remote'). Default: 'local'",
        default="local",
    )
    parser.add_argument(
        "-H", "--host", help="Connect to remote frida-server on HOST", default=None
    )

    args = parser.parse_args()
    outfile = args.outfile
    session = None

    try:
        if args.host:
            device_manager = frida.get_device_manager()
            device = device_manager.add_remote_device(args.host)
            print(f"[*] Attempting to use remote device: {device.id} at {args.host}")
        else:
            device = frida.get_device(args.device)
            print(f"[*] Using device: {device.id} ({device.name})")

        target_pid = -1
        try:
            target_pid = int(args.target)
            print(f"[*] Target specified as PID: {target_pid}")
        except ValueError:
            print(
                f"[*] Target specified as name: '{args.target}'. Searching for PID..."
            )
            try:
                target_pid = device.get_process(args.target).pid
                print(f"[*] Found process '{args.target}' with PID {target_pid}.")
            except frida.ProcessNotFoundError:
                print(
                    f"[-] Error: Process '{args.target}' not found on device '{device.id}'. Searching all processes..."
                )
                found_processes = [
                    p
                    for p in device.enumerate_processes()
                    if args.target == p.name or args.target == str(p.pid)
                ]
                if not found_processes:
                    print(
                        f"[-] Error: Could not find process matching '{args.target}' on device '{device.id}'."
                    )
                    sys.exit(1)
                elif len(found_processes) > 1:
                    print(f"[-] Warning: Multiple processes match '{args.target}':")
                    for p_info in found_processes:
                        print(f"    PID: {p_info.pid}, Name: {p_info.name}")
                    target_pid = found_processes[0].pid
                    print(f"    Using PID: {target_pid} (the first match).")
                else:
                    target_pid = found_processes[0].pid
                    print(
                        f"[*] Found process '{found_processes[0].name}' with PID {target_pid}."
                    )

        if target_pid == -1:
            print(f"[-] Error: Could not determine PID for target '{args.target}'.")
            sys.exit(1)

        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGTERM, sigint_handler)

        whitelist_modules_js = json.dumps(
            args.whitelist_modules if args.whitelist_modules else ["all"]
        )
        threadlist_js_raw = args.thread_id if args.thread_id else ["all"]
        threadlist_js_processed = (
            ["all"]
            if "all" in threadlist_js_raw
            else [int(item) for item in threadlist_js_raw if item.isdigit()]
        )
        if (
            not threadlist_js_processed and "all" not in threadlist_js_raw
        ):  # if list is empty and 'all' wasn't specified
            print(
                "[-] No valid thread IDs provided and 'all' not specified. Defaulting to 'all'."
            )
            threadlist_js_processed = ["all"]
        elif any(not item.isdigit() for item in args.thread_id if item != "all"):
            print(
                f"[-] Warning: Some non-integer thread IDs ignored: {[item for item in args.thread_id if not item.isdigit() and item != 'all'] }"
            )

        json_threadlist = json.dumps(threadlist_js_processed)

        print(f"[*] Attaching to PID '{target_pid}' on device '{device.id}'...")
        session = device.attach(target_pid)
        print("[+] Attached. Loading script...")

        script_text = js % (whitelist_modules_js, json_threadlist)
        script = session.create_script(script_text)
        script.on("message", on_message)
        script.load()
        print("[+] Script loaded.")

        print("[*] Now collecting info. Press Ctrl+C to terminate and save.")
        sys.stdin.read()

    except frida.TransportError as e:
        print(f"[!] Frida TransportError: {e}.")
    except frida.InvalidOperationError as e:
        print(f"[!] Frida InvalidOperationError: {e}.")
    except frida.ProcessNotFoundError:
        print(
            f"[-] Error: Process {target_pid if 'target_pid' in locals() and target_pid != -1 else args.target} not found or terminated."
        )
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt received (Ctrl+C).")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        import traceback

        traceback.print_exc()
    finally:
        print("[*] Detaching from process (if attached)...")
        if session:
            try:
                # It's good practice to unload the script before detaching
                # Check if script object exists and is loaded
                if "script" in locals() and script and script.is_loaded:
                    script.unload()
                session.detach()
                print("[+] Detached successfully.")
            except (
                frida.InvalidOperationError
            ) as e:  # Can happen if process already dead
                print(
                    f"[-] Error during detach/unload (process might have already exited): {e}"
                )
            except Exception as e:
                print(f"[!] Error during cleanup: {e}")

        save_coverage()
        print("[!] Frida DRcov script finished.")
        # sys.exit(0) # Let Python exit naturally after main finishes unless os._exit was called


if __name__ == "__main__":
    main()
