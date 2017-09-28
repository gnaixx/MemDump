LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

#so名
LOCAL_MODULE    := memdump

#默认ARM指令
#LOCAL_ARM_MODE := arm

#编译文件
LOCAL_SRC_FILES := main.c

#本地依赖包
LOCAL_LDLIBS += -llog

#编译可执行库
include $(BUILD_EXECUTABLE)