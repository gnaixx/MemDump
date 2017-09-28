# MemDump

**Android memory dump**

```bash
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
        
exmaple:
>> python3 build.py build
>> python3 build.py push
>> python3 build.py pull dump-mem.so
>> python3 build.py clean

>> python3 build.py com.example.gnaixx.demo libxxx.so dump-xxx.so
>> python3 build.py 23293 0x11111-0x22222 dump-xxx.so
```
