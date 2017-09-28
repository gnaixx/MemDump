#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>

#define MAX_BUFF_LEN     1024
#define MAX_SEGMENT_SIZE 5120

typedef unsigned long ulong;

typedef struct segment {
    ulong start;
    ulong end;
    char module_name[MAX_BUFF_LEN];
} segment;

void str_tolower(char *str)
{
    int i;
    for (i = 0; i < strlen(str); i++) {
        str[i] = (char) tolower(str[i]);
    }
}

int exec_command(const char* cmd, const char *feature, char *res)
{
    char buff[MAX_BUFF_LEN];
    FILE *fp = popen(cmd, "r");
    if (fp == NULL){
        printf("[*] Exec popen failed {%d, %s}\n", errno, strerror(errno));
        return -1;
    }
    while (fgets(buff, sizeof(buff), fp) != NULL){
        if (strstr(buff, feature) != NULL){
            strcpy(res, buff);
            return 0;
        }
    }
    fclose(fp);
    fp = NULL;
    return -2;
}

int get_process_pid(const char *process)
{
    char cmd[MAX_BUFF_LEN];
    char buff[MAX_BUFF_LEN];
    char running_process[MAX_BUFF_LEN];
    pid_t pid = 0;

    //search by ps commamd
    sprintf(cmd, "ps | grep %s", process);
    int res_code = exec_command(cmd, process, buff);
    if(res_code != 0){
        printf("[-] Exec command: %s failed\n", cmd);
    } else {
        pid_t running_pid;
        sscanf(buff, "%*s\t%d  %*d\t%*d %*d %*x %*x %*c %s", &running_pid, running_process);
        if (strcmp(running_process, process) == 0){
            pid = running_pid;
        }
    }

    //search by cmdline file
    if (pid > 0){
        return pid;
    }else{
        char file_name[MAX_BUFF_LEN];
        DIR *dir_proc;
        FILE *fp;
        if ((dir_proc = opendir("/proc")) == NULL){
            printf("[*] Exec opendir failed {%d, %s}\n", errno, strerror(errno));
            return 0;
        }
        struct dirent *dirent;
        while ((dirent = readdir(dir_proc)) != NULL){
            sprintf(file_name, "/proc/%s/cmdline", dirent->d_name);
            fp = fopen(file_name, "r");
            if (fp == NULL){
                continue;
            }
            fscanf(fp, "%s", running_process);
            fclose(fp);
            fp = NULL;

            if (strcmp(running_process, process) == 0){
                pid = (uint32_t)atoi(dirent->d_name);
                break;
            }
        }
        closedir(dir_proc);
        return pid;
    }
}

int get_sub_pid(int pid) {
    char task_path[MAX_BUFF_LEN];
    sprintf(task_path, "/proc/%d/task/", pid);
    DIR *root_path = opendir(task_path);
    if (root_path == NULL) {
        printf("[-] Open dir %s failed {%d, %s}\n", task_path, errno, strerror(errno));
        return -1;
    }

    struct dirent *dirent = NULL;
    struct dirent *last_dirent = NULL;
    while ((dirent = readdir(root_path)) != NULL) {
        last_dirent = dirent;
    }
    if (last_dirent == NULL) {
        printf("[-] Last dirent is null\n");
        return -1;
    }
    closedir(root_path);
    return atoi(last_dirent->d_name);
}

int attach_process(pid_t pid, int *handle) {
    char buff[MAX_BUFF_LEN];
    sprintf(buff, "/proc/%d/mem", pid);
    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (ret != 0) {
        printf("[-] Attach %d failed {%d, %s}\n", pid, errno, strerror(errno));
        return -1;
    } else {
        *handle = open(buff, O_RDONLY);
        if (handle == 0) {
            printf("[-] Open %s failed: %d, %s\n", buff, errno, strerror(errno));
            return -1;
        }
        return 0;
    }
}

int detach_process(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
      perror(NULL);
      return -1;
    }
    return 0;
}

int read_maps(pid_t pid, segment *segments, int *segment_size)
{
    char maps_path[MAX_BUFF_LEN];
    sprintf(maps_path, "/proc/%d/maps", pid);
    FILE *maps_handle = fopen(maps_path, "r");
    if (maps_handle == NULL) {
        printf("[-] Open %s failed: %d, %s\n", maps_path, errno, strerror(errno));
        return -1;
    }

    int index = 0;
    ulong start, end;
    char line[MAX_BUFF_LEN];
    char module_name[MAX_BUFF_LEN];
    char pre_module_name[MAX_BUFF_LEN];
    while (fgets(line, MAX_BUFF_LEN, maps_handle) != NULL) {
        memset(module_name, 0, MAX_BUFF_LEN);
        //printf("[*] Content: %s", line);
        int rv = sscanf(line, "%lx-%lx %*s %*s %*s %*s %s", &start, &end, module_name);
        //printf("[*] Segment information:{start:0x%lx, end:0x%lx, name:%s}\n", start, end, module_name);
        if (rv != 3) {
            //printf("[-] Scanf failed: %d, %s\n", errno, strerror(errno));
            continue;
        } else {
            str_tolower(module_name);
            if (strcmp(pre_module_name, module_name) == 0) {
                if (segments[index - 1].end < end) {
                    segments[index - 1].end = end;
                }
            } else {
                strcpy(pre_module_name, module_name);
                strcpy(segments[index].module_name, module_name);
                segments[index].start = start;
                segments[index].end = end;
                index++;
            }
        }
    }
    *segment_size = index;
    fclose(maps_handle);
    maps_handle = NULL;
    return 0;
}

int dump_module(int mem_handle, ulong start, ulong end, const char* output)
{
    ulong size = end - start;
    int res_code = 0;
    if (lseek(mem_handle, start, SEEK_SET) != -1) {
        char *content = (char *) malloc(size * sizeof(char));
        ssize_t dump_size = read(mem_handle, content, size);

        FILE *output_handle = fopen(output, "wb");
        if (fwrite(content, sizeof(char), dump_size, output_handle) == dump_size) {
            res_code = 0;
        } else {
            printf("[-] Write %s failed: %d, %s\n", output, errno, strerror(errno));
            res_code = -1;
        }
        fclose(output_handle);
        free(content);
        content = NULL;
        return res_code;
    } else {
        printf("[-] Lseek %d failed: %d, %s\n", mem_handle, errno, strerror(errno));
        return -1;
    }
}

int main(int argc, char const *argv[])
{
    char process[MAX_BUFF_LEN] = "";
    pid_t pid;
    ulong start;
    ulong end;
    char module[MAX_BUFF_LEN] = "";
    char output[MAX_BUFF_LEN] = "";

    strncpy(process, argv[1], strlen(argv[1]));
    pid = atoi(argv[2]);
    start = atoll(argv[3]);
    end = atoll(argv[4]);
    strncpy(module, argv[5], strlen(argv[5]));
    strncpy(output, argv[6], strlen(argv[6]));

    printf("[+] Input args: {process:%s, pid:%d, start:0x%lx, end:0x%lx, module:%s, output:%s}\n",
           process, pid, start, end, module, output);

    //check process or pid
    if (pid == 0){
        if (strncmp(process, "-", 1) == 0){
            printf("[-] Must input process or pid\n");
            return -1;
        }
        pid = get_process_pid(process);
        if(pid == 0 ){
            printf("[-] Can't find pid by process name\n");
            return -1;
        } else{
            printf("[+] Get %s pid: %d\n", process, pid);
        }
    }else{
        char cmd[MAX_BUFF_LEN];
        char buff[MAX_BUFF_LEN];
        char pid_str[MAX_BUFF_LEN];
        sprintf(pid_str, "%d", pid);
        sprintf(cmd, "ps | grep %d", pid);
        int res_code = exec_command(cmd, pid_str, buff);
        if(res_code != 0){
            printf("[-] Can't find process by pid: %d\n", pid);
            return -1; 
        }
        printf("[+] Find process by pid: %d\n", pid);
    }

    //get sub_pid
    int sub_pid = get_sub_pid(pid);
    if(sub_pid != 0){
        printf("[+] Get sub pid:%d success\n", sub_pid);
        pid = sub_pid;
    }

    int mem_handle = 0;
    int res_code = attach_process(pid, &mem_handle);
    if(res_code != 0){
        printf("[-] Attach pid:%d failed", pid);
        return -1;
    }
    printf("[+] Attach pid:%d success, handle: %d\n", pid, mem_handle);

    segment *segments = malloc(sizeof(segment) * MAX_SEGMENT_SIZE);
    int segment_size = 0;
    res_code = read_maps(pid, segments, &segment_size);
    if(res_code != 0){
        printf("[-] Read segment information failed\n");
    }
    printf("[+] Read segment information success, size: %d\n", segment_size);

    //check module name or scope address
    if(start == 0 || end == 0){
        if(strncmp(module, "-", 1) == 0){
            printf("[-] Must input available module name or scope address\n");
            return -1;
        }
        int i = 0;
        int has_module = 0;
        for(i=0; i<segment_size; i++){
            if(strstr(segments[i].module_name, module) != NULL){
                start = segments[i].start;
                end = segments[i].end;
                has_module = 1;
                printf("[+] Target segment information: {start:0x%lx, end:0x%lx, name:%s}\n", start, end, module);
                break;
            }
        }
        if(has_module == 0){
            printf("[-] Check input module name: %s\n", module);
            return -1;
        }
    }

    res_code = dump_module(mem_handle, start, end, output);
    if (res_code == 0){
        printf("[+] Dump %s success", output);
    }

    detach_process(pid);
    close(mem_handle);
    free(segments);
    return 0;
}