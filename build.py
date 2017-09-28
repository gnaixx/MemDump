# -*- coding: utf-8 -*-
import sys
import os
import shutil

usage_code = """
Usage: build.py action [process|pid scope|module output]

    action:
        build       Build for script
        push        Push script to device
        run         Run script dump memory
        pull        Pull dump file
        clean       Delete build file
        
    options(run):
        process     Target process name
        pid         Target process pid
        scope       Dump memory scope, such as:0x11111111-0x22222222
        module      Dump memory name
        output      Output file name        
"""

def parse_args():
    
    args = sys.argv[1:]
    options = {}
    if len(args) == 1 and args[0] != "run":
        options["action"] = args[0]
    elif len(args) == 2 and args[0] == "pull":
        options["action"] = args[0]
        options["output"] = args[1]
    elif len(args) == 4:
        options["action"] = args[0]
        if args[1].isdigit():
            options["pid"] = int(args[1])
        else:
            options["process"] = args[1]
        
        if args[2].startswith("0x", 0, 2):
            scope = args[2]
            options["start"] = int(scope.split("-", 1)[0], 16)
            options["end"] = int(scope.split("-", 1)[1], 16)
        else:
            options["module"] = args[2]
        options["output"] =  args[3]
    else:
        print(usage_code)
        exit()
    return options


def push(memdump):
    print("[*] Push memory dump script...")
    ret = os.popen("adb shell getprop | grep ro.product.cpu.abi").read()
    abi = ret.split(":", 1)[1][2:-2]
    if abi.startswith("x86"):
        os.system("adb push libs/x86/%s /data/local/tmp/" % memdump)
    elif abi.startswith("arm"):
        os.system("adb push libs/armeabi/%s /data/local/tmp/" % memdump)
    os.system("adb shell su -c 'chmod 777 /data/local/tmp/%s'" % memdump)


def build():
    print("[+] Build memory dump script...")
    os.system("ndk-build -B APP_ABI='x86 armeabi'")


def run(memdump, options):
    process = "-" if "process" not in options else options["process"]
    pid = 0 if "pid" not in options else options["pid"]
    start = 0 if "start" not in options else options["start"]
    end = 0 if "end" not in options else options["end"]
    module = "-" if "module" not in options else options["module"].lower()
    output = "dump_mem.xx" if "output" not in options else "data/local/tmp/" + options["output"]

    args = ("%s %d 0x%x 0x%x %s %s" % (process, pid, start, end, module, output))
    command = ("/data/local/tmp/%s %s" % (memdump, args))
    print("[*] Run script with command: %s" % command)
    os.system("adb shell su -c '%s'" % command)


def pull(output):
    print("[+] Pull dump file: %s" % output)

    os.system("adb shell su -c 'cp /data/local/tmp/%s /sdcard/'" % output);
    output_path = os.path.join(os.getcwd(), "output")
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    os.system("adb pull /sdcard/%s %s" % (output, output_path))
    os.system("adb shell su -c 'rm /sdcard/%s'" % output);


def clean():
    print("[-] Clean path of libs/ obj/ output/")
    libs_path = os.path.join(os.getcwd(), "libs")
    obj_path = os.path.join(os.getcwd(), "obj")
    if os.path.exists(libs_path) or os.path.exists(obj_path):
        shutil.rmtree(libs_path)
        shutil.rmtree(obj_path)

    output_path = os.path.join(os.getcwd(), "output")
    if os.path.exists(output_path):
        shutil.rmtree(output_path)


if __name__ == '__main__':
    options = parse_args()
    # print(options)

    memdump = "memdump"
    action = options["action"]
    if action == "build":
        build()
    elif action == "push":
        push(memdump)
    elif action == "run":
        run(memdump, options)
    elif action == "pull":
        pull(options["output"])
    elif action == "clean":
        clean()
    elif action == "rerun":
        clean()
        build()
        push(memdump)
        run(memdump, options)
    else:
        print(usage_code)