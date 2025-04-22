#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h> 
#include <sys/ipc.h>  
#include <sys/shm.h> 
#include <ctype.h> 
#include <sys/resource.h>
#include "src/linked_list.c"
#define MAX_HISTORY 100
#define MAX_OPEN_FILES 100
#define PATH_MAX 4096
char *history[MAX_HISTORY];
int history_count = 0;
int openFileCount = 0;
extern char **environ; 
int ext_var1, ext_var2, ext_var3;
int ext_init_var1 = 10, ext_init_var2 = 20, ext_init_var3 = 30;
static int static_var1, static_var2, static_var3;
static int static_init_var1 = 40, static_init_var2 = 50, static_init_var3 = 60;
typedef struct MemoryBlock {
    void *address;               
    size_t size;                 
    time_t allocation_time;      
    char allocation_type[20];    
    int file_descriptor;         
    char file_path[256];         
    key_t shared_key;            
    struct MemoryBlock *next;    
} MemoryBlock;
typedef struct SearchNode {
    char *directory;
    struct SearchNode *next;
} SearchNode;
SearchNode *searchList = NULL;
MemoryBlock *head = NULL;  
typedef struct BackgroundJob {
    pid_t pid;
    char command[256];
    time_t launch_time;
    int priority;
    struct BackgroundJob *next;
} BackgroundJob;
BackgroundJob *jobList = NULL;
typedef struct Job {
    pid_t pid;             
    int priority;          
    char status[10];       
    char command[256];     
    char launch_time[20];  
    int return_value;      
    struct Job *next;
} Job;
Job *job_list = NULL; 
void list_directory_recursive(const char *dir_path, int long_flag, int hid_flag, int link_flag, int acc_flag);
void revlist_directory_recursive(const char *dir_path, int long_flag, int hid_flag, int link_flag, int acc_flag);
void fgCommand(char *args[]);
void processInput(char *input, NodeList *openFiles, char *envp[]);
void freeMemoryBlocks() {
    MemoryBlock *current = head;
    while (current != NULL) {
        MemoryBlock *temp = current;
        if (strcmp(temp->allocation_type, "mmap") == 0) {
            munmap(temp->address, temp->size);
            close(temp->file_descriptor);
        } else if (strcmp(temp->allocation_type, "malloc") == 0) {
            free(temp->address);
        }
        free(temp);
        current = current->next;
    }
    head = NULL;
}
void deljobs(char *option) {
    Job *current = job_list, *prev = NULL, *temp = NULL;
    while (current != NULL) {
        int remove = 0;
        if (option == NULL || strcmp(option, "") == 0) {
            if (strcmp(current->status, "ACTIVO") == 0) {
                remove = 1;
            }
        } else if (strcmp(option, "-term") == 0) {
            if (strcmp(current->status, "TERMINADO") == 0) {
                remove = 1;
            }
        } else if (strcmp(option, "-sig") == 0) {
            if (strcmp(current->status, "SIGNALED") == 0) {
                remove = 1;
            }
        }
        if (remove) {
            printf("Removing job with PID: %d (%s)\n", current->pid, current->command);
            if (prev == NULL) {
                job_list = current->next;  
            } else {
                prev->next = current->next;  
            }
            temp = current;
            current = current->next;
            free(temp);
        } else {
            prev = current;
            current = current->next;
        }
    }
    if (job_list == NULL) {
        printf("Job list is now empty.\n");
    }
}
void add_job(pid_t pid, int priority, const char *command) {
    Job *new_job = (Job *)malloc(sizeof(Job));
    new_job->pid = pid;
    new_job->priority = priority;
    strncpy(new_job->command, command, sizeof(new_job->command) - 1);
    new_job->command[sizeof(new_job->command) - 1] = '\0';
    time_t now = time(NULL);
    struct tm *tinfo = localtime(&now);
    strftime(new_job->launch_time, sizeof(new_job->launch_time), "%Y/%m/%d %H:%M:%S", tinfo);
    strcpy(new_job->status, "ACTIVO");
    new_job->return_value = 0;
    new_job->next = job_list;
    job_list = new_job;
}
void update_job_status() {
    Job *current = job_list;
    int status;
    while (current) {
        pid_t result = waitpid(current->pid, &status, WNOHANG);
        if (result == 0) {
            strcpy(current->status, "ACTIVO");
        } else if (result > 0) {
            strcpy(current->status, "TERMINADO");
            if (WIFEXITED(status)) {
                current->return_value = WEXITSTATUS(status);
            }
        }
        current = current->next;
    }
}
void list_jobs() {
    update_job_status();
    Job *current = job_list;
    while (current) {
        if(current->priority == 0)
        printf("%6d   %-8s p=- %s %-8s (%03d) %s\n",
               current->pid, getenv("USER"), current->launch_time,
               current->status, current->return_value, current->command);
        else   
            printf("%6d   %-8s p=%-4d %s %-8s (%03d) %s\n",
               current->pid, getenv("USER"), current->priority, current->launch_time,
               current->status, current->return_value, current->command);
        current = current->next;
    }
}
char* args_to_string(char *args[]) {
    static char buffer[256];
    buffer[0] = '\0';
    for (int i = 1; args[i] != NULL; i++) {
        strcat(buffer, args[i]);
        strcat(buffer, " ");
    }
    buffer[strlen(buffer) - 1] = '\0'; 
    return buffer;
}
void backpri(char *args[], int priority) {
    if (args[0] == NULL) {
        printf("Error: No command specified for backpri.\n");
        return;
    }
    struct stat file_stat;
    if (stat(args[0], &file_stat) == -1) {
        perror("Error retrieving file information");
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return;
    }
    if (pid == 0) { 
        if (setpriority(PRIO_PROCESS, 0, priority) == -1) {
            fprintf(stderr, "Error: Unable to set priority: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        printf("Iniciando shell..\n");
        printf("Ejecutar %s -p para importar el path\n", args[0]);
        char date_buffer[50];
        struct tm *creation_time = localtime(&file_stat.st_ctime);
        strftime(date_buffer, sizeof(date_buffer), "%d/%m/%Y, %H:%M:%S", creation_time);
        printf("version del shell 4.K.12 Fecha ejecutable: %s\n", date_buffer);
        execvp(args[0], args);
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else { 
        char command[256];
        snprintf(command, sizeof(command), "%s %s", args[0], args_to_string(args)); 
        add_job(pid, priority, command); 
        printf("Started background process with PID: %d\n", pid);
    }
}
void addJob(pid_t pid, const char *command, int priority) {
    BackgroundJob *newJob = malloc(sizeof(BackgroundJob));
    if (!newJob) {
        perror("Failed to allocate memory for background job");
        return;
    }
    newJob->pid = pid;
    strncpy(newJob->command, command, sizeof(newJob->command) - 1);
    newJob->command[sizeof(newJob->command) - 1] = '\0';
    newJob->launch_time = time(NULL);
    newJob->priority = priority;
    newJob->next = jobList;
    jobList = newJob;
    printf("Background job started: PID=%d, Command=%s, Priority=%d\n", pid, command, priority);
}
void backCommand(char *args[]) {
    pid_t pid;
    if ((pid = fork()) < 0) {
        perror("Fork failed");
        return;
    }
    if (pid == 0) {
        printf("Iniciando shell..\n");
        printf("Ejecutar %s -p para importar el path\n", args[1]);
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char formatted_time[64];
        strftime(formatted_time, sizeof(formatted_time), "%d/%m/%Y, %H:%M:%S", t);
        printf("version del shell 4.K.12 Fecha ejecutable: %s\n", formatted_time);
        fflush(stdout);
        if (execvp(args[1], &args[1]) < 0) {
            perror("Exec failed");
            exit(1);
        }
    } else {
        char command[256];
        snprintf(command, sizeof(command), "%s %s", args[0], args_to_string(args)); 
        add_job(pid, 0, command); 
        printf("Proceso en segundo plano iniciado con PID: %d\n", pid);
    }
}
char *extractExecutableAndArgs(char *args[], int start, char ***execArgs) {
    int count = 0;
    while (args[start + count] != NULL) {
        count++;
    }
    *execArgs = malloc((count + 1) * sizeof(char *));
    if (*execArgs == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        (*execArgs)[i] = args[start + i];
    }
    (*execArgs)[count] = NULL;
    return (*execArgs)[0]; 
}
void fgpri(char *args[], int priority) {
    pid_t pid = fork();
    if (pid == 0) {
        if (setpriority(PRIO_PROCESS, getpid(), priority) == -1) {
            perror("Error setting priority");
            exit(1);
        }
        printf("Iniciando %s..\n", args[0]); 
        printf("Ejecutar %s -p para importar el path\n", args[0]);
        printf("version del shell %s Fecha ejecutable: %s, %s\n", 
            "4.K.12", 
            __DATE__, 
            __TIME__  
        );
        execvp(args[0], args); 
        perror("Error executing program");
        exit(1);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    } else {
        perror("Error creating process");
    }
}
char *Ejecutable(char *cmd) {
    static char path[1024];
    struct stat st;
    char *path_env = getenv("PATH");
    char *dir;
    if (!cmd || cmd[0] == '/' || strncmp(cmd, "./", 2) == 0 || strncmp(cmd, "../", 3) == 0) {
        return cmd;
    }
    dir = strtok(path_env, ":");
    while (dir) {
        snprintf(path, sizeof(path), "%s/%s", dir, cmd);
        if (lstat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return path; 
        }
        dir = strtok(NULL, ":");
    }
    return cmd;
}
   void fgCommand(char *args[]) {
    pid_t pid;
    if (args[1] == NULL) {
        printf("Usage: fg <program> [arguments...]\n");
        return;
    }
    printf("Iniciando shell..\n");
    if ((pid = fork()) == 0) {
        printf("Ejecutar %s -p para importar el path\n", args[1]);
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char date_time[50];
        strftime(date_time, sizeof(date_time), "%d/%m/%Y, %H:%M:%S", tm_info);
        printf("version del shell 4.K.12 Fecha ejecutable: %s\n", date_time);
        if (execve(args[1], &args[1], environ) == -1) {
            perror("Execution failed");
            exit(errno);
        }
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Process finished with exit code %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Process terminated by signal %d\n", WTERMSIG(status));
        }
    } else {
        perror("Fork failed");
    }
}
void addDirectory(const char *dir) {
    SearchNode *newNode = (SearchNode *)malloc(sizeof(SearchNode));
    newNode->directory = strdup(dir);
    newNode->next = searchList;
    searchList = newNode;
    printf("Directory added: %s\n", dir);
}
void deleteDirectory(const char *dir) {
    SearchNode *current = searchList, *prev = NULL;
    while (current != NULL) {
        if (strcmp(current->directory, dir) == 0) {
            if (prev == NULL) { 
                searchList = current->next;
            } else {
                prev->next = current->next;
            }
            printf("Directory deleted: %s\n", dir);
            free(current->directory);
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
    printf("Directory not found: %s\n", dir);
}
void clearSearchList() {
    SearchNode *current = searchList;
    while (current != NULL) {
        SearchNode *temp = current;
        current = current->next;
        free(temp->directory);
        free(temp);
    }
    searchList = NULL;
    printf("Search list cleared.\n");
}
void execpriCommand(char *args[], char **envp) {
    if (args[1] == NULL || args[2] == NULL) {
        fprintf(stderr, "Usage: execpri <priority> <program> [arguments...]\n");
        return;
    }
    int priority = atoi(args[1]);
    if (priority < -20 || priority > 19) {
        fprintf(stderr, "Error: Priority must be between -20 and 19.\n");
        return;
    }
    if (args[2] == NULL) {
        fprintf(stderr, "Error: No executable specified.\n");
        return;
    }
    if (setpriority(PRIO_PROCESS, getpid(), priority) == -1) {
        perror("Error setting priority");
        return;
    }
    printf("Executing with priority %d...\n", priority);
    printf("Executing command: %s\n", args[2]);
    if (execve(args[2], &args[2], envp) == -1) {
        perror("Execve error");
    }
}
void execCommand(char *args[], char **envp) {
    char **newEnv = NULL;
    int envCount = 0;
    int start = 1; 
    while (args[start] != NULL && strchr(args[start], '=')) {
        envCount++;
        start++;
    }
    if (envCount > 0) {
        newEnv = malloc((envCount + 1) * sizeof(char *));
        for (int i = 0; i < envCount; i++) {
            newEnv[i] = args[1 + i];
        }
        newEnv[envCount] = NULL;
    }
    if (args[start] == NULL) {
        fprintf(stderr, "Error: No executable specified.\n");
        if (newEnv) free(newEnv);
        return;
    }
    struct stat fileInfo;
    if (stat(args[start], &fileInfo) != 0) {
        perror("Error retrieving file info");
        if (newEnv) free(newEnv);
        return;
    }
    char formatted_date[64];
    strftime(formatted_date, sizeof(formatted_date), "%d/%m/%Y, %H:%M:%S", localtime(&fileInfo.st_mtime));
    printf("Iniciando shell..\n");
    printf("Ejecutar %s -p para importar el path\n", args[start]);
    printf("version del shell 4.K.12 Fecha ejecutable: %s\n", formatted_date);
    printf("*Allocate**\n");
    printf("*Deallocate\n");
    printf("*Deallocate**\n");
    printf("Executing command: %s\n", args[start]);
    if (execve(args[start], &args[start], newEnv ? newEnv : envp) == -1) {
        perror("Execve error");
    }
    if (newEnv) free(newEnv);
}
char **build_env(char *vars[], int count) {
    char **new_env = malloc((count + 1) * sizeof(char *));
    if (!new_env) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < count; i++) {
        for (char **env = environ; *env != NULL; env++) {
            if (strncmp(*env, vars[i], strlen(vars[i])) == 0 && (*env)[strlen(vars[i])] == '=') {
                new_env[i] = *env;
                break;
            }
        }
    }
    new_env[count] = NULL;
    return new_env;
}
int is_env_var(const char *var) {
    for (char **env = environ; *env != NULL; env++) {
        if (strncmp(*env, var, strlen(var)) == 0 && (*env)[strlen(var)] == '=') {
            return 1;
        }
    }
    return 0;
}
void show_environ_addresses(char *envp[]) {
    printf("environ:   0x%p (almacenado en 0x%p)\n",
           (void *)environ,          
           (void *)&environ);        
    printf("main arg3: 0x%p (almacenado en 0x%p)\n",
           (void *)envp,             
           (void *)&envp);           
}
void show_environ() {
    char **env = environ;
    int index = 0;
    printf("Environment Variables:\n");
    while (*env != NULL) {
        printf("0x%p->environ[%d]=(0x%p) %s\n",
               (void *)&environ[index], 
               index,                  
               (void *)*env,           
               *env);                  
        env++;
        index++;
    }
}
void subsvar(int argc, char *args[], char *envp[]) {
    char *flag = args[1];
    char *v1 = args[2];
    char *v2 = args[3];
    char *val = args[4];
    char *v1_value = getenv(v1);
    if (v1_value == NULL) {
        fprintf(stderr, "Error: Variable %s not found in the environment.\n", v1);
        return;
    }
    if (strcmp(flag, "-a") == 0) {
        for (char **current = envp; *current != NULL; current++) {
            if (strncmp(*current, v1, strlen(v1)) == 0 && (*current)[strlen(v1)] == '=') {
                printf("Con arg3 main %s=%s(%p) -> %s=%s\n", v1, v1_value, (void *)v1_value, v2, val);
                snprintf(*current, strlen(v2) + strlen(val) + 2, "%s=%s", v2, val);
                return;
            }
        }
        fprintf(stderr, "Error: Variable %s not found in envp.\n", v1);
    } else if (strcmp(flag, "-e") == 0) {
        for (char **current = environ; *current != NULL; current++) {
            if (strncmp(*current, v1, strlen(v1)) == 0 && (*current)[strlen(v1)] == '=') {
                printf("Con environ %s=%s(%p) -> %s=%s\n", v1, v1_value, (void *)v1_value, v2, val);
                snprintf(*current, strlen(v2) + strlen(val) + 2, "%s=%s", v2, val);
                return;
            }
        }
        fprintf(stderr, "Error: Variable %s not found in environ.\n", v1);
    } else {
        fprintf(stderr, "Error: Invalid flag. Use -a or -e.\n");
    }
}
void change_variable(char *mode, char *var, char *val, char *envp[]) {
    if (strcmp(mode, "-a") == 0) {
        for (int i = 0; envp[i] != NULL; i++) {
            if (strncmp(envp[i], var, strlen(var)) == 0 && envp[i][strlen(var)] == '=') {
                snprintf(envp[i], strlen(var) + strlen(val) + 2, "%s=%s", var, val);
                printf("Con arg3 main %s=%s(%p)\n", var, val, envp[i]);
                return;
            }
        }
        printf("Variable %s not found in arg3 main.\n", var);
    } else if (strcmp(mode, "-e") == 0) {
        for (char **env = environ; *env != NULL; env++) {
            if (strncmp(*env, var, strlen(var)) == 0 && (*env)[strlen(var)] == '=') {
                snprintf(*env, strlen(var) + strlen(val) + 2, "%s=%s", var, val);
                printf("Con environ %s=%s(%p)\n", var, val, *env);
                return;
            }
        }
        printf("Variable %s not found in environ.\n", var);
    } else if (strcmp(mode, "-p") == 0) {
        char *buffer = malloc(strlen(var) + strlen(val) + 2);
        if (!buffer) {
            perror("Memory allocation failed");
            return;
        }
        sprintf(buffer, "%s=%s", var, val);
        if (putenv(buffer) == 0) {
            printf("Con putenv %s(%p)\n", buffer, buffer);
        } else {
            perror("putenv failed");
        }
    } else {
        printf("Invalid mode. Use -a, -e, or -p.\n");
    }
}
void show_variable_info(char *vars[], int count, char *envp[]) {
    for (int i = 0; i < count; i++) {
        char *var_name = vars[i];
        char *value_arg3 = NULL;
        char *value_environ = NULL;
        char *value_getenv = getenv(var_name); 
        char *envp_entry = NULL;
        char *environ_entry = NULL;
        for (char **current = envp; *current != NULL; current++) {
            if (strncmp(*current, var_name, strlen(var_name)) == 0 && (*current)[strlen(var_name)] == '=') {
                envp_entry = *current;
                value_arg3 = strchr(*current, '=') + 1;
                break;
            }
        }
        for (char **current = environ; *current != NULL; current++) {
            if (strncmp(*current, var_name, strlen(var_name)) == 0 && (*current)[strlen(var_name)] == '=') {
                environ_entry = *current;
                value_environ = strchr(*current, '=') + 1;
                break;
            }
        }
        if (value_arg3 && envp_entry) {
            printf("Con arg3 main %s=%s(%p) @%p\n", var_name, value_arg3, (void *)value_arg3, (void *)envp_entry);
        } else {
            printf("Variable '%s' no encontrada en arg3 de main.\n", var_name);
        }
        if (value_environ && environ_entry) {
            printf("  Con environ %s=%s(%p) @%p\n", var_name, value_environ, (void *)value_environ, (void *)environ_entry);
        } else {
            printf("  Variable '%s' no encontrada en environ.\n", var_name);
        }
        if (value_getenv) {
            printf("   Con getenv %s(%p)\n", value_getenv, (void *)value_getenv);
        } else {
            printf("   Con getenv '%s' no encontrada.\n", var_name);
        }
    }
}
void importPath() {
    char *path = getenv("PATH");
    if (path == NULL) {
        printf("PATH environment variable not found.\n");
        return;
    }
    clearSearchList(); 
    char *token = strtok(path, ":");
    while (token != NULL) {
        addDirectory(token);
        token = strtok(NULL, ":");
    }
    printf("PATH imported into search list.\n");
}
void displaySearchList() {
    SearchNode *current = searchList;
    if (current == NULL) {
        printf("Search list is empty.\n");
        return;
    }
    printf("Search list directories:\n");
    while (current != NULL) {
        printf("  %s\n", current->directory);
        current = current->next;
    }
}
void Cmd_fork (char *tr[]) {
    pid_t pid;
    if ((pid=fork())==0) {
        printf ("ejecutando proceso %d\n", getpid());
    } else if (pid!=-1)
        waitpid(pid, NULL, 0);
}
void show_variable_with_address(char *vars[], int count, char *envp[]) {
    for (int i = 0; i < count; i++) {
        char *var_name = vars[i];
        char *value_getenv = getenv(var_name); 
        char *value_environ = NULL;           
        char *entry_address = NULL;           
        for (char **current = envp; *current != NULL; current++) {
            if (strncmp(*current, var_name, strlen(var_name)) == 0 && (*current)[strlen(var_name)] == '=') {
                value_environ = strchr(*current, '=') + 1; 
                entry_address = *current;                 
                break;
            }
        }
        if (value_environ) {
            printf("With environ %s=%s(%p) @%p\n", var_name, value_environ, (void *)value_environ, (void *)entry_address);
        } else {
            printf("Variable: %s not found in environ.\n", var_name);
        }
        if (value_getenv) {
            printf("With getenv %s(%p)\n", value_getenv, (void *)value_getenv);
        } else {
            printf("Variable: %s not found with getenv.\n", var_name);
        }
    }
}
void view_process_credentials() {
    uid_t real_uid = getuid();       
    uid_t effective_uid = geteuid(); 
    printf("Real UID: %u\n", real_uid);
    printf("Effective UID: %u\n", effective_uid);
}
void recursive_function(int n) {
    char automatic_array[2048];
    static char static_array[2048];
    printf("parametro:  %d(%p) array %p, arr estatico %p\n",
           n, (void *)&n, (void *)automatic_array, (void *)static_array);
    if (n <= 0) {
        return;
    }
    recursive_function(n - 1);
}
void write_to_fd(int fd, const void *addr, size_t cont) {
    if (fd < 0) {
        fprintf(stderr, "Invalid file descriptor: %d\n", fd);
        return;
    }
    if (!addr) {
        fprintf(stderr, "Invalid memory address.\n");
        return;
    }
    ssize_t bytes_written = write(fd, addr, cont);
    if (bytes_written < 0) {
        perror("Error writing to file descriptor");
    } else {
        printf("Wrote %zd bytes from memory at address %p to file descriptor %d\n", bytes_written, addr, fd);
    }
}
void read_from_fd(int fd, void *addr, size_t cont) {
    if (fd < 0) {
        fprintf(stderr, "Invalid file descriptor: %d\n", fd);
        return;
    }
    if (!addr) {
        fprintf(stderr, "Invalid memory address.\n");
        return;
    }
    ssize_t bytes_read = read(fd, addr, cont);
    if (bytes_read < 0) {
        perror("Error reading from file descriptor");
    } else {
        printf("Read %zd bytes into memory at address %p\n", bytes_read, addr);
    }
}
void write_memory_to_file(const char *file, const void *addr, size_t cont) {
    FILE *fp = fopen(file, "wb");
    if (!fp) {
        perror("Error opening file");
        return;
    }
    size_t bytes_written = fwrite(addr, 1, cont, fp);
    if (bytes_written < cont) {
        perror("Error writing to file");
    } else {
        printf("Wrote %zu bytes from memory at address %p to file %s\n", bytes_written, addr, file);
    }
    fclose(fp);
}
void read_file_to_memory(const char *file, void *addr, size_t cont) {
    FILE *fp = fopen(file, "rb");
    if (!fp) {
        perror("Error opening file");
        return;
    }
    size_t bytes_read = fread(addr, 1, cont, fp);
    if (bytes_read < cont && ferror(fp)) {
        perror("Error reading file");
    } else {
        printf("Read %zu bytes into memory at address %p\n", bytes_read, addr);
    }
    fclose(fp);
}
void get_pmap_output() {
    FILE *file = fopen("/proc/self/maps", "r");
    if (!file) {
        perror("Error opening /proc/self/maps");
        return;
    }
    char line[256];
    size_t total_kb = 0;
    while (fgets(line, sizeof(line), file)) {
        char perms[8], offset[16], dev[8], inode[16], path[128] = "[ anon ]";
        unsigned long start, end;
        int read_items;
        read_items = sscanf(line, "%lx-%lx %7s %15s %7s %15s %127[^\n]",
                            &start, &end, perms, offset, dev, inode, path);
        if (read_items >= 5) {
            size_t size_kb = (end - start) / 1024; 
            total_kb += size_kb; 
            printf("%-20lx %5luK %-5s %s\n",
                   start,           
                   size_kb,         
                   perms,           
                   path             
            );
        }
    }
    fclose(file);
    printf(" total             %5luK\n", total_kb);
}
void memory_blocks() {
    MemoryBlock *current = head;
    if (current == NULL) {
        printf("No memory blocks allocated.\n");
        return;
    }
    printf("Allocated memory blocks:\n");
    while (current != NULL) {
        printf("Address: %p, Size: %zu bytes, Allocation Type: %s\n",
               current->address, current->size, current->allocation_type);
        current = current->next;
    }
}
void memory_vars() {
    printf("External Variables: %p, %p, %p\n", (void *)&ext_var1, (void *)&ext_var2, (void *)&ext_var3);
    printf("External Initialized Variables: %p, %p, %p\n", (void *)&ext_init_var1, (void *)&ext_init_var2, (void *)&ext_init_var3);
    printf("Static Variables: %p, %p, %p\n", (void *)&static_var1, (void *)&static_var2, (void *)&static_var3);
    printf("Static Initialized Variables: %p, %p, %p\n", (void *)&static_init_var1, (void *)&static_init_var2, (void *)&static_init_var3);
    int auto_var1, auto_var2, auto_var3;
    printf("Automatic Variables: %p, %p, %p\n", (void *)&auto_var1, (void *)&auto_var2, (void *)&auto_var3);
}
void func1() {}
void func2() {}
void func3() {}
void memory_funcs() {
    printf("Program func      %p,    %p,    %p\n", (void *)func1, (void *)func2, (void *)func3);
    printf("Func libr      %p,    %p,    %p\n", (void *)malloc, (void *)free, (void *)printf);
}
void memdump(void *addr, size_t count) {
    unsigned char *ptr = (unsigned char *)addr;  
    size_t i;
    for (i = 0; i < count; i++) {
        printf("%02x ", ptr[i]);
        if (ptr[i] >= 32 && ptr[i] <= 126) {  
            printf("%c ", ptr[i]);
        } else {
            printf(". ");
        }
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");  
}
void memfill(void *addr, size_t count, char ch) {
    memset(addr, (int)ch, count);
    printf("Filled memory starting at address %p with character '%c' for %zu bytes.\n", addr, ch, count);
}
void deallocate_malloc(size_t size) {
    MemoryBlock *current = head;
    while (current != NULL) {
        if (strcmp(current->allocation_type, "malloc") == 0 && current->size == size) {
            freeMemoryBlocks(current->address);
            printf("Successfully deallocated malloc memory block of size %zu bytes.\n", size);
            return;
        }
        current = current->next;
    }
    printf("No malloc memory block of size %zu found\n", size);
}
void deallocate_mmap(const char *file_path) {
    MemoryBlock *current = head;
    MemoryBlock *previous = NULL;
    while (current != NULL) {
        if (strcmp(current->allocation_type, "mmap") == 0 && strcmp(current->file_path, file_path) == 0) {
            munmap(current->address, current->size);
            close(current->file_descriptor);
            printf("Unmapped mmap memory block for file '%s' at address %p\n", file_path, current->address);
            if (previous == NULL) {
                head = current->next;
            } else {
                previous->next = current->next;
            }
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    printf("No mmap memory block found for file '%s'\n", file_path);
}
void deallocate_shared(key_t key) {
    MemoryBlock *current = head;
    MemoryBlock *previous = NULL;
    while (current != NULL) {
        if (strcmp(current->allocation_type, "shared") == 0 && current->shared_key == key) {
            if (shmdt(current->address) == -1) {
                perror("Failed to detach shared memory");
            } else {
                printf("Detached shared memory with key %d at address %p\n", key, current->address);
                if (previous == NULL) {
                    head = current->next;
                } else {
                    previous->next = current->next;
                }
                free(current);
            }
            return;
        }
        previous = current;
        current = current->next;
    }
    printf("No shared memory block with key %d found\n", key);
}
void detach_shared_memory(void *address) {
    if (shmdt(address) == -1) {
        perror("Failed to detach shared memory");
    } else {
        printf("Detached shared memory at address %p\n", address);
    }
}
void deallocate_delkey(key_t key) {
    MemoryBlock *current = head;
    MemoryBlock *previous = NULL;
    while (current != NULL) {
        if (strcmp(current->allocation_type, "shared") == 0 && current->shared_key == key) {
            printf("Removing shared memory block with key %d from the list, but not detaching.\n", key);
            if (previous == NULL) {
                head = current->next;
            } else {
                previous->next = current->next;
            }
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    printf("No shared memory block with key %d found\n", key);
}
void deallocate_addr(void *addr) {
    MemoryBlock *current = head;
    MemoryBlock *previous = NULL;
    while (current != NULL) {
        if (current->address == addr) {
            if (strcmp(current->allocation_type, "malloc") == 0) {
                free(current->address);
                printf("Successfully deallocated malloc memory block at address %p\n", addr);
            }
            else if (strcmp(current->allocation_type, "shared") == 0) {
                if (shmdt(current->address) == -1) {
                    perror("Failed to detach shared memory");
                } else {
                    printf("Detached shared memory at address %p\n", addr);
                }
            }
            else if (strcmp(current->allocation_type, "mmap") == 0) {
                if (munmap(current->address, current->size) == -1) {
                    perror("Failed to unmap memory");
                } else {
                    close(current->file_descriptor);
                    printf("Unmapped mmap memory block for file '%s' at address %p\n", current->file_path, addr);
                }
            }
            if (previous == NULL) {
                head = current->next;
            } else {
                previous->next = current->next;
            }
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    printf("No memory block found at address %p\n", addr);
}
void add_shared_memory_block(void *address, size_t size, key_t key) {
    MemoryBlock *new_block = (MemoryBlock *)malloc(sizeof(MemoryBlock));
    if (new_block == NULL) {
        perror("Failed to allocate memory for new memory block");
        return;
    }
    new_block->address = address;
    new_block->size = size;
    new_block->allocation_time = time(NULL);
    strncpy(new_block->allocation_type, "shared", sizeof(new_block->allocation_type) - 1);
    new_block->allocation_type[sizeof(new_block->allocation_type) - 1] = '\0';
    new_block->shared_key = key;  
    new_block->next = head;
    head = new_block;
}
void *allocate_shared_memory(key_t key, size_t size) {
    int shm_id;
    void *shm_addr;
    int flags = (size > 0) ? (IPC_CREAT | IPC_EXCL | 0666) : 0666;
    shm_id = shmget(key, size, flags);
    if (shm_id == -1) {
        if (errno == EEXIST) {
            perror("Shared memory segment already exists");
        } else {
            perror("Error creating or finding shared memory segment");
        }
        return NULL;
    }
    shm_addr = shmat(shm_id, NULL, 0);
    if (shm_addr == (void *)-1) {
        perror("Error attaching shared memory segment");
        return NULL;
    }
    if ((ssize_t)size < 0) {
        printf("Attached to existing shared memory: Key=%d, Address=%p\n", key, shm_addr);
    }
    return shm_addr;
}
void *map_file_to_memory(const char *file, int protection, MemoryBlock **mapped_block) {
    (void)mapped_block;
    int df, map = MAP_PRIVATE, modo = O_RDONLY;
    struct stat s;
    void *mapped_addr;
    if (protection & PROT_WRITE) {
        modo = O_RDWR;
    }
    if (stat(file, &s) == -1 || (df = open(file, modo)) == -1) {
        perror("Error opening file");
        return NULL;
    }
    if ((mapped_addr = mmap(NULL, s.st_size, protection, map, df, 0)) == MAP_FAILED) {
        perror("Error mapping file");
        close(df);
        return NULL;
    }
    MemoryBlock *new_block = (MemoryBlock *)malloc(sizeof(MemoryBlock));
    if (new_block == NULL) {
        perror("Failed to allocate memory for new memory block");
        munmap(mapped_addr, s.st_size);
        close(df);
        return NULL;
    }
    new_block->address = mapped_addr;
    new_block->size = s.st_size;
    new_block->allocation_time = time(NULL);
    strncpy(new_block->allocation_type, "mmap", sizeof(new_block->allocation_type) - 1);
    new_block->allocation_type[sizeof(new_block->allocation_type) - 1] = '\0';
    new_block->file_descriptor = df;
    strncpy(new_block->file_path, file, sizeof(new_block->file_path) - 1);
    new_block->file_path[sizeof(new_block->file_path) - 1] = '\0';
    new_block->next = head;
    head = new_block;
    printf("Mapped file '%s' with size %zu at address %p\n", file, new_block->size, new_block->address);
    return mapped_addr;
}
void add_memory_block(void *address, size_t size, const char *type) {
    MemoryBlock *new_block = (MemoryBlock *)malloc(sizeof(MemoryBlock));
    if (new_block == NULL) {
        perror("Failed to allocate memory for new memory block");
        return;
    }
    new_block->address = address;
    new_block->size = size;
    new_block->allocation_time = time(NULL);
    strncpy(new_block->allocation_type, type, sizeof(new_block->allocation_type) - 1);
    new_block->allocation_type[sizeof(new_block->allocation_type) - 1] = '\0';
    new_block->next = head;
    head = new_block;
}
void erase(const char *path) {
    if (remove(path) == 0) {
        printf("Successfully deleted: %s\n", path);
    } else {
        printf("Error deleting file or directory: %s\n", path);
    }
}
void delrec(const char *path){
    DIR *dir;
    struct dirent *entry;
    char copyPath[1024];
    if ((dir = opendir(path)) == NULL) {
        perror("opendir() error");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
            int type = entry->d_type;
            char *name = entry->d_name;
            snprintf(copyPath, sizeof(copyPath), "%s/%s", path, name);
            if (type == 8){
                erase(copyPath);
            }else{
                delrec(copyPath);
            }
        }
    }
    erase(path);
    closedir(dir);
}
void reclist(int argc, char *argv[]) {
    int long_flag = 0, hid_flag = 0, link_flag = 0, acc_flag = 0;
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-') {
        if (strcmp(argv[optind], "-long") == 0) {
            long_flag = 1;
        } else if (strcmp(argv[optind], "-hid") == 0) {
            hid_flag = 1;
        } else if (strcmp(argv[optind], "-link") == 0) {
            link_flag = 1;
        } else if (strcmp(argv[optind], "-acc") == 0) {
            acc_flag = 1;
        } else {
            printf("Unknown option: %s\n", argv[optind]);
            return;
        }
        optind++;
    }
    if (optind >= argc) {
        list_directory_recursive(".", long_flag, hid_flag, link_flag, acc_flag);
    } else {
        for (int i = optind; i < argc; i++) {
            list_directory_recursive(argv[i], long_flag, hid_flag, link_flag, acc_flag);
        }
    }
}
void list_directory_recursive(const char *dir_path, int long_flag, int hid_flag, int link_flag, int acc_flag) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;
    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        return;
    }
    printf("************%s\n", dir_path);
    while ((entry = readdir(dir)) != NULL) {
        if (!hid_flag && entry->d_name[0] == '.') {
            continue;
        }
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
        if (lstat(filepath, &fileStat) < 0) {
            perror("Error retrieving file information");
            continue;
        }
        if (acc_flag) {
            char accTime[20];
            strftime(accTime, sizeof(accTime), "%Y/%m/%d-%H:%M", localtime(&fileStat.st_atime));
            printf("%8ld  %s %s\n", fileStat.st_size, accTime, entry->d_name);
        } else if (link_flag) {
            if (entry->d_name[0] != '.') {
                printf("%8ld  %s\n", fileStat.st_size, entry->d_name);
            }
        } else if (long_flag && entry->d_name[0] != '.') {
            char modTime[20];
            strftime(modTime, sizeof(modTime), "%Y/%m/%d-%H:%M", localtime(&fileStat.st_mtime));
            printf("%s   %lu (%7lu)  %-8s %-8s %c%c%c%c%c%c%c%c%c%c %8ld %s\n",
                   modTime,
                   (unsigned long)fileStat.st_nlink,
                   (unsigned long)fileStat.st_ino,
                   getpwuid(fileStat.st_uid)->pw_name,
                   getgrgid(fileStat.st_gid)->gr_name,
                   (S_ISDIR(fileStat.st_mode)) ? 'd' : '-',
                   (fileStat.st_mode & S_IRUSR) ? 'r' : '-',
                   (fileStat.st_mode & S_IWUSR) ? 'w' : '-',
                   (fileStat.st_mode & S_IXUSR) ? 'x' : '-',
                   (fileStat.st_mode & S_IRGRP) ? 'r' : '-',
                   (fileStat.st_mode & S_IWGRP) ? 'w' : '-',
                   (fileStat.st_mode & S_IXGRP) ? 'x' : '-',
                   (fileStat.st_mode & S_IROTH) ? 'r' : '-',
                   (fileStat.st_mode & S_IWOTH) ? 'w' : '-',
                   (fileStat.st_mode & S_IXOTH) ? 'x' : '-',
                   fileStat.st_size,
                   entry->d_name);
        } else if (!long_flag) {
            printf("%6ld  %s\n", fileStat.st_size, entry->d_name);
        }
    }
    closedir(dir);
    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!hid_flag && entry->d_name[0] == '.') {
            continue;
        }
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
        if (lstat(filepath, &fileStat) < 0) {
            continue;
        }
        if (S_ISDIR(fileStat.st_mode)) {
            list_directory_recursive(filepath, long_flag, hid_flag, link_flag, acc_flag);
        }
    }
    closedir(dir);
}
void revlist(int argc, char *argv[]) {
    int long_flag = 0, hid_flag = 0, link_flag = 0, acc_flag = 0;
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-') {
        if (strcmp(argv[optind], "-long") == 0) {
            long_flag = 1;
        } else if (strcmp(argv[optind], "-hid") == 0) {
            hid_flag = 1;
        } else if (strcmp(argv[optind], "-link") == 0) {
            link_flag = 1;
        } else if (strcmp(argv[optind], "-acc") == 0) {
            acc_flag = 1;
        } else {
            printf("Unknown option: %s\n", argv[optind]);
            return;
        }
        optind++;
    }
    if (optind >= argc) {
        revlist_directory_recursive(".", long_flag, hid_flag, link_flag, acc_flag);
    } else {
        for (int i = optind; i < argc; i++) {
            revlist_directory_recursive(argv[i], long_flag, hid_flag, link_flag, acc_flag);
        }
    }
}
void revlist_directory_recursive(const char *dir_path, int long_flag, int hid_flag, int link_flag, int acc_flag) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;
    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!hid_flag && entry->d_name[0] == '.') {
            continue;
        }
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
        if (lstat(filepath, &fileStat) < 0) {
            continue;
        }
        if (S_ISDIR(fileStat.st_mode)) {
            revlist_directory_recursive(filepath, long_flag, hid_flag, link_flag, acc_flag);
        }
    }
    closedir(dir);
    if ((dir = opendir(dir_path)) == NULL) {
        perror("Error opening directory");
        return;
    }
    printf("************%s\n", dir_path);
    while ((entry = readdir(dir)) != NULL) {
        if (!hid_flag && entry->d_name[0] == '.') {
            continue;
        }
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
        if (lstat(filepath, &fileStat) < 0) {
            perror("Error retrieving file information");
            continue;
        }
        if (long_flag) {
            char modTime[20];
            strftime(modTime, sizeof(modTime), "%Y/%m/%d-%H:%M", localtime(&fileStat.st_mtime));
            printf("%s   %lu (%7lu)  %-8s %-8s %c%c%c%c%c%c%c%c%c%c %8ld %s\n",
                   modTime,
                   (unsigned long)fileStat.st_nlink,
                   (unsigned long)fileStat.st_ino,
                   getpwuid(fileStat.st_uid)->pw_name,
                   getgrgid(fileStat.st_gid)->gr_name,
                   (S_ISDIR(fileStat.st_mode)) ? 'd' : '-',
                   (fileStat.st_mode & S_IRUSR) ? 'r' : '-',
                   (fileStat.st_mode & S_IWUSR) ? 'w' : '-',
                   (fileStat.st_mode & S_IXUSR) ? 'x' : '-',
                   (fileStat.st_mode & S_IRGRP) ? 'r' : '-',
                   (fileStat.st_mode & S_IWGRP) ? 'w' : '-',
                   (fileStat.st_mode & S_IXGRP) ? 'x' : '-',
                   (fileStat.st_mode & S_IROTH) ? 'r' : '-',
                   (fileStat.st_mode & S_IWOTH) ? 'w' : '-',
                   (fileStat.st_mode & S_IXOTH) ? 'x' : '-',
                   fileStat.st_size,
                   entry->d_name);
        } else if (!long_flag) {
            printf("%6ld  %s\n", fileStat.st_size, entry->d_name);
        }
    }
    closedir(dir);
}
void listdir(int argc, char *argv[]) {
    int long_flag = 0, hid_flag = 0, link_flag = 0, acc_flag = 0;
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-') {
        if (strcmp(argv[optind], "-long") == 0) {
            long_flag = 1;
        } else if (strcmp(argv[optind], "-hid") == 0) {
            hid_flag = 1;
        } else if (strcmp(argv[optind], "-link") == 0) {
            link_flag = 1;
        } else if (strcmp(argv[optind], "-acc") == 0) {
            acc_flag = 1;
        } else {
            printf("Unknown option: %s\n", argv[optind]);
            return;
        }
        optind++;
    }
    for (int i = optind; i < argc; i++) {
        DIR *dir;
        struct dirent *entry;
        struct stat fileStat;
        if ((dir = opendir(argv[i])) == NULL) {
            perror("Error opening directory");
            continue;
        }
        printf("Listing contents of directory: %s\n", argv[i]);
        while ((entry = readdir(dir)) != NULL) {
            if (!hid_flag && entry->d_name[0] == '.') {
                continue;
            }
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", argv[i], entry->d_name);
            if (lstat(filepath, &fileStat) < 0) {
                perror("Error retrieving file information");
                continue;
            }
            if (long_flag) {
                char modTime[20];
                strftime(modTime, sizeof(modTime), "%Y/%m/%d-%H:%M", localtime(&fileStat.st_mtime));
                printf("%s   %lu (%7lu)  %-8s %-8s %c%c%c%c%c%c%c%c%c%c %8ld %s\n",
                       modTime,
                       (unsigned long)fileStat.st_nlink,
                       (unsigned long)fileStat.st_ino,
                       getpwuid(fileStat.st_uid)->pw_name,
                       getgrgid(fileStat.st_gid)->gr_name,
                       (S_ISDIR(fileStat.st_mode)) ? 'd' : '-',
                       (fileStat.st_mode & S_IRUSR) ? 'r' : '-',
                       (fileStat.st_mode & S_IWUSR) ? 'w' : '-',
                       (fileStat.st_mode & S_IXUSR) ? 'x' : '-',
                       (fileStat.st_mode & S_IRGRP) ? 'r' : '-',
                       (fileStat.st_mode & S_IWGRP) ? 'w' : '-',
                       (fileStat.st_mode & S_IXGRP) ? 'x' : '-',
                       (fileStat.st_mode & S_IROTH) ? 'r' : '-',
                       (fileStat.st_mode & S_IWOTH) ? 'w' : '-',
                       (fileStat.st_mode & S_IXOTH) ? 'x' : '-',
                       fileStat.st_size,
                       entry->d_name);
            } else if (acc_flag) {
                char accTime[20];
                strftime(accTime, sizeof(accTime), "%Y/%m/%d-%H:%M", localtime(&fileStat.st_atime));
                printf("%8ld  %s  %s\n", fileStat.st_size, accTime, entry->d_name);
            } else if (link_flag && S_ISLNK(fileStat.st_mode)) {
                char link_target[1024];
                ssize_t len = readlink(filepath, link_target, sizeof(link_target) - 1);
                if (len != -1) {
                    link_target[len] = '\0';
                    printf("%8ld  %s -> %s\n", fileStat.st_size, entry->d_name, link_target);
                } else {
                    perror("Error reading symbolic link");
                }
            } else {
                printf("%8ld  %s\n", fileStat.st_size, entry->d_name);
            }
        }
        closedir(dir);
        printf("----------------------------------------\n");
    }
}
void listfile(int argc, char *argv[]) {
    printf("Arguments received by listfile():\n");
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    int long_flag = 0, link_flag = 0, acc_flag = 0;
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-') {
        if (strcmp(argv[optind], "-long") == 0) {
            long_flag = 1;
        } else if (strcmp(argv[optind], "-link") == 0) {
            link_flag = 1;
        } else if (strcmp(argv[optind], "-acc") == 0) {
            acc_flag = 1;
        } else {
            printf("Unknown option: %s\n", argv[optind]);
            return;
        }
        optind++;
    }
    if (long_flag) {
        printf("Long flag detected.\n");
    }
    if (link_flag) {
        printf("Link flag detected.\n");
    }
    if (acc_flag) {
        printf("Access flag detected.\n");
    }
    for (int i = optind; i < argc; i++) {
        struct stat fileStat;
        if (lstat(argv[i], &fileStat) < 0) {
            perror("Error retrieving file information");
            continue;
        }
        printf("File: %s\n", argv[i]);
        if (long_flag) {
            printf("Size: %ld bytes\n", fileStat.st_size);
            printf("Permissions: ");
            printf((S_ISDIR(fileStat.st_mode)) ? "d" : "-");
            printf((fileStat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fileStat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fileStat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fileStat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fileStat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fileStat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fileStat.st_mode & S_IROTH) ? "r" : "-");
            printf((fileStat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fileStat.st_mode & S_IXOTH) ? "x" : "-");
            printf("\n");
            char creationTime[20];
            strftime(creationTime, sizeof(creationTime), "%Y-%m-%d %H:%M:%S", localtime(&fileStat.st_ctime));
            printf("Creation date: %s\n", creationTime);
        }
        if (acc_flag) {
            char accTime[20];
            strftime(accTime, sizeof(accTime), "%Y-%m-%d %H:%M:%S", localtime(&fileStat.st_atime));
            printf("Last accessed: %s\n", accTime);
        }
        if (link_flag && S_ISLNK(fileStat.st_mode)) {
            char link_target[1024];
            ssize_t len = readlink(argv[i], link_target, sizeof(link_target) - 1);
            if (len != -1) {
                link_target[len] = '\0';
                printf("Symbolic link target: %s\n", link_target);
            } else {
                perror("Error reading symbolic link");
            }
        }
        if (long_flag || acc_flag || link_flag) {
            printf("----------------------------------------\n");
        }
    }
}
int makeDir(const char *dirname) {
    if (mkdir(dirname, 0777) == -1) {
        perror("Error creating directory");
        return -1;
    }
    return 0;
}
int makeFile(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error creating file");
        return -1;
    }
    fclose(file);
    return 0;
}
void printPrompt() {
    printf("myshell> ");
}
void readEntry(char *buffer, size_t buffer_size) {
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        perror("Error reading input");
        exit(1);
    }
}
int TrocearCadena(char *cadena, char *trozos[]) {
    int i = 1;
    if ((trozos[0] = strtok(cadena, " \n\t")) == NULL) {
        return 0;
    }
    while ((trozos[i] = strtok(NULL, " \n\t")) != NULL) {
        i++;
    }
    return i;
}
void store_in_history(char *input) {
    if (history_count < MAX_HISTORY) {
        history[history_count++] = strdup(input);
    } else {
        free(history[0]);
        for (int i = 1; i < MAX_HISTORY; i++) {
            history[i - 1] = history[i];
        }
        history[MAX_HISTORY - 1] = strdup(input);
    }
}
void show_history(char *arg, NodeList *openFiles, char *envp[]) {
    if (strcmp(arg, "-100") != 0){
        int n = atoi(arg); 
        if (strcmp(arg, "-c") == 0) {
    for (int i = 0; i < history_count; i++) {
        free(history[i]);
    }
    history_count = 0;
    printf("History cleared.\n");
    return;
}
        if (n > 0 && n <= history_count) {
            printf("Repeating command %d: %s\n", n, history[n - 1]);
            processInput(history[n - 1], openFiles, 0); 
        } else if (n < 0 && -n <= history_count) {
            for (int i = history_count + n - 1; i < history_count - 1; i++) {
                printf("%d %s\n", i + 1, history[i]); 
            }
        } else {
            printf("Invalid argument for historic command.\n");
        }
    }
    else{
        for (int i = 0; i < history_count; i++) {
            printf("%d %s\n", i + 1, history[i]);
        }
    }
}
void change_directory(char *path) {
    if (path == NULL) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("Current directory: %s\n", cwd);
        } else {
            perror("getcwd() error");
        }
    } else if (chdir(path) != 0) {
        perror("chdir() error");
    }
}
void show_date(int show_time, int show_date) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char date_buffer[11];
    char time_buffer[9];
    if (show_date) {
        strftime(date_buffer, sizeof(date_buffer), "%d/%m/%Y", tm_info);
        printf("Date: %s\n", date_buffer);
    }
    if (show_time) {
        strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S", tm_info);
        printf("Time: %s\n", time_buffer);
    }
}
void open_file_with_modes(const char *file, char *modes[], int mode_count) {
    int flags = 0;
    for (int i = 0; i < mode_count; i++) {
        if (strcmp(modes[i], "cr") == 0) {  
            flags |= O_CREAT;
        } else if (strcmp(modes[i], "ap") == 0) {
            flags |= O_APPEND;
        } else if (strcmp(modes[i], "ex") == 0) {
            flags |= O_EXCL;
        } else if (strcmp(modes[i], "ro") == 0) {
            flags |= O_RDONLY;
        } else if (strcmp(modes[i], "rw") == 0) {
            flags |= O_RDWR;
        } else if (strcmp(modes[i], "wo") == 0) {
            flags |= O_WRONLY;
        } else if (strcmp(modes[i], "tr") == 0) {
            flags |= O_TRUNC;
        } else {
            printf("Invalid mode: %s\n", modes[i]);
            return;
        }
    }
    if ((flags & O_RDONLY) && (flags & (O_WRONLY | O_RDWR))) {
        printf("Conflicting modes: Cannot use ro with rw or wo\n");
        return;
    }
    int fd = open(file, flags, 0644);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }
    printf("File '%s' opened with descriptor: %d\n", file, fd);
    for (int fd_check = 0; fd_check < 20; fd_check++) {
        char *description = "no usado";
        char *access_mode = ""; 
        off_t offset = -1;
        char path[PATH_MAX] = ""; 
        int flags_check = fcntl(fd_check, F_GETFL);
        if (flags_check != -1) {
            if (fd_check == 0) description = "entrada estandar";
            else if (fd_check == 1) description = "salida estandar";
            else if (fd_check == 2) description = "error estandar";
            else description = "archivo abierto";
            if ((flags_check & O_ACCMODE) == O_RDONLY) access_mode = "O_RDONLY";
            else if ((flags_check & O_ACCMODE) == O_WRONLY) access_mode = "O_WRONLY";
            else if ((flags_check & O_ACCMODE) == O_RDWR) access_mode = "O_RDWR";
            offset = lseek(fd_check, 0, SEEK_CUR);
            if (offset == -1 && errno == ESPIPE) {
                offset = -2; 
            }
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd_check);
            char resolved_path[PATH_MAX] = "unknown";
            if (readlink(path, resolved_path, sizeof(resolved_path)) != -1) {
                strncpy(path, resolved_path, sizeof(path));
            } else {
                strcpy(path, "no path");
            }
        }
        if (offset == -1) {
            printf("descriptor: %d, offset: (  )-> %s %s %s\n", fd_check, path, description, access_mode);
        } else if (offset == -2) {
            printf("descriptor: %d, offset: (unsupported)-> %s %s %s\n", fd_check, path, description, access_mode);
        } else {
            printf("descriptor: %d, offset: (%ld)-> %s %s %s\n", fd_check, offset, path, description, access_mode);
        }
    }
    close(fd); 
}
void list_file_descriptors() {
    for (int fd_check = 0; fd_check < 20; fd_check++) {
        char *description = "no usado";  
        char *access_mode = "";          
        off_t offset = -1;               
        char path[PATH_MAX] = "";        
        int flags_check = fcntl(fd_check, F_GETFL);
        if (flags_check != -1) {  
            if (fd_check == 0) {
                description = "entrada estandar";  
            } else if (fd_check == 1) {
                description = "salida estandar";  
            } else if (fd_check == 2) {
                description = "error estandar";  
            } else {
                description = "archivo abierto";  
            }
            if ((flags_check & O_ACCMODE) == O_RDONLY) {
                access_mode = "O_RDONLY";  
            } else if ((flags_check & O_ACCMODE) == O_WRONLY) {
                access_mode = "O_WRONLY";  
            } else if ((flags_check & O_ACCMODE) == O_RDWR) {
                access_mode = "O_RDWR";    
            }
            offset = lseek(fd_check, 0, SEEK_CUR);
            if (offset == -1 && errno == ESPIPE) {
                offset = -2;  
            }
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd_check);
            char resolved_path[PATH_MAX] = "unknown";
            if (readlink(path, resolved_path, sizeof(resolved_path)) != -1) {
                strncpy(path, resolved_path, sizeof(path));
            } else {
                strcpy(path, "no path");
            }
        }
        if (offset == -1) {
            printf("descriptor: %d, offset: (  )-> %s %s %s\n", fd_check, path, description, access_mode);
        } else if (offset == -2) {
            printf("descriptor: %d, offset: (unsupported)-> %s %s %s\n", fd_check, path, description, access_mode);
        } else {
            printf("descriptor: %d, offset: (%ld)-> %s %s %s\n", fd_check, offset, path, description, access_mode);
        }
    }
}
void list_open_files(NodeList *openFiles) {
    Node *current = openFiles->head;
    printf("Open files:\n");
    while (current != NULL){
        printf("FD: %d, File: %s, Mode: %s\n", current->fd, current->filename, current->mode);
        current = current->next;
    }
}
void close_file(int fd, NodeList *openFiles) {
    if (close(fd) == -1) {
        perror("Failed to close the file");
    } else {
        Node *current = getNodeByFD(fd, openFiles);
        removeNode(openFiles, current);
        printf("File descriptor %d closed successfully.\n", fd);
    }
}
void show_info() {
    struct utsname sysinfo;
    if (uname(&sysinfo) == 0) {
        printf("System info:\n");
        printf("  Sysname: %s\n", sysinfo.sysname);
        printf("  Nodename: %s\n", sysinfo.nodename);
        printf("  Release: %s\n", sysinfo.release);
        printf("  Version: %s\n", sysinfo.version);
        printf("  Machine: %s\n", sysinfo.machine);
    } else {
        perror("uname");
    }
}
void duplicate_fd(int old_fd, NodeList *openFile) {
    int new_fd = dup(old_fd);
    if (new_fd == -1) {
        perror("Error duplicating file");
    } else {
        if (openFileCount < MAX_OPEN_FILES) {
            Node *oldNode = getNodeByFD(old_fd, openFile);
            Node *newNode = createNode(new_fd, oldNode->filename, oldNode->mode);
            addNode(openFile, newNode);
            openFileCount++;
            printf("File descriptor %d duplicated to: %d\n", old_fd, new_fd);
        } else {
            printf("Reached maximum open file limit\n");
        }
    }
}
enum Command {
    CMD_UNKNOWN,
    CMD_AUTHORS,
    CMD_PID,
    CMD_PPID,
    CMD_CD,
    CMD_DATE,
    CMD_HISTORIC,
    CMD_OPEN,
    CMD_CLOSE,
    CMD_DUP,
    CMD_INFOSYS,
    CMD_MAKEFILE,
    CMD_HELP,
    CMD_EXIT,
    CMD_MAKEDIR,
    CMD_LISTFILE,
    CMD_CWD,
    CMD_LISTDIR,
    CMD_ERASE,
    CMD_FORCE_DELETE,
    CMD_REVLIST,
    CMD_RECLIST,
    CMD_ALLOCATE,
    CMD_DEALLOCATE,
    CMD_MEMFILL,
    CMD_MEMDUMP,
    CMD_MEMORY,
    CMD_READFILE,
    CMD_WRITEFILE,
    CMD_READ,
    CMD_WRITE,
    CMD_RECURSE,
    CMD_GETUID,
    CMD_SETUID,
    CMD_SHOWVAR,
    CMD_CHANGEVAR,
    CMD_SUBSVAR,
    CMD_ENVIRON,
    CMD_FORK,
    CMD_SEARCH,
    CMD_EXEC,
    CMD_EXECPRI,
    CMD_FG,
    CMD_FGPRI,
    CMD_BACK,
    CMD_BACKPRI,
    CMD_LISTJOBS,
    CMD_DELJOBS
};
enum Command getCommandType(const char *cmd) {
    if (strcmp(cmd, "authors") == 0) return CMD_AUTHORS;
    if (strcmp(cmd, "pid") == 0) return CMD_PID;
    if (strcmp(cmd, "ppid") == 0) return CMD_PPID;
    if (strcmp(cmd, "cd") == 0) return CMD_CD;
    if (strcmp(cmd, "date") == 0) return CMD_DATE;
    if (strcmp(cmd, "historic") == 0) return CMD_HISTORIC;
    if (strcmp(cmd, "open") == 0) return CMD_OPEN;
    if (strcmp(cmd, "close") == 0) return CMD_CLOSE;
    if (strcmp(cmd, "dup") == 0) return CMD_DUP;
    if (strcmp(cmd, "infosys") == 0) return CMD_INFOSYS;
    if (strcmp(cmd, "makefile") == 0) return CMD_MAKEFILE;
    if (strcmp(cmd, "makedir") == 0) return CMD_MAKEDIR;
    if (strcmp(cmd, "listfile") == 0) return CMD_LISTFILE;
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "command") == 0) return CMD_HELP;
    if (strcmp(cmd, "cwd") == 0) return CMD_CWD;
    if (strcmp(cmd, "listdir") == 0) return CMD_LISTDIR;
    if (strcmp(cmd, "erase") == 0) return CMD_ERASE;
    if (strcmp(cmd, "delrec") == 0) return CMD_FORCE_DELETE;
    if (strcmp(cmd, "reclist") == 0) return CMD_RECLIST;
    if (strcmp(cmd, "revlist") == 0) return CMD_REVLIST;
    if (strcmp(cmd, "allocate") == 0) return CMD_ALLOCATE;
    if (strcmp(cmd, "deallocate") == 0) return CMD_DEALLOCATE;
    if (strcmp(cmd, "memfill") == 0) return CMD_MEMFILL;
    if (strcmp(cmd, "memdump") == 0) return CMD_MEMDUMP;
    if (strcmp(cmd, "memory") == 0) return CMD_MEMORY;
    if (strcmp(cmd, "readfile") == 0) return CMD_READFILE;
    if (strcmp(cmd, "writefile") == 0) return CMD_WRITEFILE;
    if (strcmp(cmd, "read") == 0) return CMD_READ;
    if (strcmp(cmd, "write") == 0) return CMD_WRITE;
    if (strcmp(cmd, "recursive") == 0) return CMD_RECURSE;
    if (strcmp(cmd, "getuid") == 0) return CMD_GETUID;
    if (strcmp(cmd, "setuid") == 0) return CMD_SETUID;
    if (strcmp(cmd, "showvar") == 0) return CMD_SHOWVAR;
    if (strcmp(cmd, "changevar") == 0) return CMD_CHANGEVAR;
    if (strcmp(cmd, "subsvar") == 0) return CMD_SUBSVAR;
    if (strcmp(cmd, "environ") == 0) return CMD_ENVIRON;
    if (strcmp(cmd, "fork") == 0) return CMD_FORK;
    if (strcmp(cmd, "search") == 0) return CMD_SEARCH;
    if (strcmp(cmd, "exec") == 0) return CMD_EXEC;
    if (strcmp(cmd, "execpri") == 0) return CMD_EXECPRI;
    if (strcmp(cmd, "fg") == 0) return CMD_FG;
    if (strcmp(cmd, "fgpri") == 0) return CMD_FGPRI;
    if (strcmp(cmd, "back") == 0) return CMD_BACK;
    if (strcmp(cmd, "backpri") == 0) return CMD_BACKPRI;
    if (strcmp(cmd, "listjobs") == 0) return CMD_LISTJOBS;
    if (strcmp(cmd, "deljobs") == 0) return CMD_DELJOBS;
    if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "bye") == 0) return CMD_EXIT;
    return CMD_UNKNOWN;
}
void processInput(char *input, NodeList *openFiles, char *envp[] ){
    char *args[64];
    input[strcspn(input, "\n")] = 0;
    store_in_history(input);
    int argc = TrocearCadena(input, args);
    if (argc == 0) return;
    enum Command cmd = getCommandType(args[0]);
    switch (cmd) {
        case CMD_AUTHORS:
            if (argc == 1 || strcmp(args[1], "-n") == 0) {
                printf("Author Names: Jokubas Klikna, Daniel Ciocan\n");
            } else if (strcmp(args[1], "-l") == 0) {
                printf("Logins: jokubas.klikna, daniel.ciocan\n");
            }else{
                printf("'authors' command accepts only -n and -l parameters\n");
            }
            break;
        case CMD_HELP:
            if (strcmp(args[0], "command") == 0){
                if (argc < 2 || strcmp(args[1], "-?") != 0){
                    printf("Did you mean 'command -?'\n");
                    break;
                }
            }
            printf("\nAvailable commands:\n\n"
                    "authors, pid, ppid, cd, date, historic, open, close, dup, infosys, makefile, makedir, listfile\n"
                    "cwd, listdir, reclist, revlist, delrec, erase, quit, exit, bye, allocate, deallocate, memfill\n"
                    "memdump, memory, readfile, writefile, read, write, recursive");
            break;  
        case CMD_PID:
            if(argc == 1)
                printf("Shell PID: %d\n", getpid());
            else
                printf("'pid' command doesn't suport any aditional parametres\n");
            break;
        case CMD_PPID:
            if(argc == 1)
                printf("Parent PID: %d\n", getppid());
            else
                printf("'ppid' command doesn't suport any aditional parametres\n");
            break;
        case CMD_CD:
            if (argc < 3)
                change_directory(args[1]);
            else
                printf("Error: Usage cd <filepath>\n");
            break;
        case CMD_DATE:
            if (argc == 1) {
                show_date(1, 1);
            } else if (strcmp(args[1], "-d") == 0) {
                show_date(0, 1);
            } else if (strcmp(args[1], "-t") == 0) {
                show_date(1, 0);
            } else {
                printf("Date comand accepts only -d and -t parameters\n");
            }
            break;
        case CMD_HISTORIC:
            if (argc == 1) {
                show_history("-100", openFiles, 0);
            } else {
                show_history(args[1], openFiles, 0);
            }
            break;
       case CMD_OPEN: {
        if (argc == 1) {
        list_file_descriptors();
        break;
    }
    if (argc < 3) {
        printf("Usage: open <file> [modes...]\n");
        break;
    }
    const char *file = args[1];
    int mode_count = argc - 2;
    char **modes = &args[2];
    open_file_with_modes(file, modes, mode_count);
    break;
}
        case CMD_CLOSE:
            if (argc == 2){
                close_file(atoi(args[1]), openFiles);
            }else{
                printf("Usage: close <file_descriptor>\n");
            }
            break;
        case CMD_DUP:
            if (argc == 2) {
                duplicate_fd(atoi(args[1]), openFiles);
            } else {
                printf("Usage: dup <file_descriptor>\n");
            }
            break;
        case CMD_INFOSYS:
            if(argc == 1)   
                show_info();
            else
                printf("'infosys' command doesn't suport any aditional parametres\n");
            break;
        case CMD_MAKEFILE:
            if (argc == 2) {
                int result = makeFile(args[1]);
                if (result == 0){
                    printf("Created: %s\n", args[1]);
                }else{
                    printf("Error: something unexpected happened\n");
                }
            } else {
                printf("Usage: makefile <filename>\n");
            }
            break;
        case CMD_MAKEDIR:
            if (argc == 2) {
                int result = makeDir(args[1]);
                if (result == 0) {
                    printf("Directory '%s' created successfully.\n", args[1]);
                }else{
                    printf("Error: something unexpected happened\n");
                }
            } else {
                printf("Usage: makedir <directory_name>\n");
            }
            break;
        case CMD_LISTFILE:
            if (argc > 1) {
                listfile(argc, args);
            } else {
                printf("Usage: listfile [-long] [-link] [-acc] <file1> <file2> ...\n");
            }
            break;
        case CMD_CWD: 
            if (argc == 1){
                char cwd[1024];
                if (getcwd(cwd, sizeof(cwd)) != NULL) {
                    printf("Current working directory: %s\n", cwd);
                } else {
                    perror("getcwd() error");
                }
                break;
            }else{
                printf("'cwd' command doesn't suport any aditional parametres\n");
            }
            break;
        case CMD_LISTDIR:
            if (argc > 1) {
                listdir(argc, args);
            } else {
                char *defaultArgs[] = {"listdir", "."};
                listdir(2, defaultArgs);
            }
            break;
        case CMD_ERASE:
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (remove(args[i]) == 0) {
                printf("%s erased\n", args[i]);
            } else {
                perror("Error erasing file");
            }
        }
    } else {
        printf("Usage: erase <file_or_directory_path> [file_or_directory_path ...]\n");
    }
    break;
        case CMD_RECLIST:
            if (argc > 1) {
                reclist(argc, args);
             } else {
                char *defaultArgs[] = {"reclist", "."};
                reclist(2, defaultArgs);
            }
            break;
        case CMD_REVLIST:
            if (argc > 1) {
                revlist(argc, args);
            } else {
                char *defaultArgs[] = {"revlist", "."};
                revlist(2, defaultArgs);
            }
            break;
        case CMD_ALLOCATE:
    if (argc == 1) {
        printf("****** List of memory blocks assigned for process %d ******\n", getpid());
        MemoryBlock *current = head;
        while (current != NULL) {
            printf("Address: %p, Size: %zu bytes, Type: %s, Allocation Time: %s",
                   current->address, current->size, current->allocation_type, ctime(&(current->allocation_time)));
            if (strcmp(current->allocation_type, "mmap") == 0) {
                printf(", File Descriptor: %d, File Path: %s\n", current->file_descriptor, current->file_path);
            } else if (strcmp(current->allocation_type, "shared") == 0) {
                printf(", Shared Key: %d\n", current->shared_key);
            } else {
                printf("\n");
            }
            current = current->next;
        }
    } 
    else if (argc == 3 && strcmp(args[1], "-malloc") == 0) {
        size_t size = (size_t)atoi(args[2]);
        if (size <= 0) {
            printf("Invalid size. Please specify a positive number of bytes.\n");
            break;
        }
        void *address = malloc(size);
        if (address != NULL) {
            add_memory_block(address, size, "malloc");
            printf("Allocated %zu bytes at address %p using malloc\n", size, address);
        } else {
            perror("Failed to allocate memory");
        }
    } 
    else if (argc == 4 && strcmp(args[1], "-createshared") == 0) {
    key_t key = (key_t)strtoul(args[2], NULL, 10);
    size_t size = (size_t)atoi(args[3]);
    if (size == 0) {
        printf("Invalid size for shared memory. Please specify a positive number of bytes.\n");
        break;
    }
    void *shared_mem = allocate_shared_memory(key, size);
    if (shared_mem == NULL) {
        perror("Failed to allocate shared memory");
    } else {
        add_shared_memory_block(shared_mem, size, key);
        printf("Created and attached shared memory segment with key %d, size %zu at address %p\n", key, size, shared_mem);
    }
}
else if (argc == 3 && strcmp(args[1], "-shared") == 0) {
    key_t key = (key_t)strtoul(args[2], NULL, 10);
    MemoryBlock *current = head;
    while (current != NULL) {
        if (strcmp(current->allocation_type, "shared") == 0 && current->shared_key == key) {
            detach_shared_memory(current->address);
            break;  
        }
        current = current->next;
    }
    void *shared_mem = allocate_shared_memory(key, 0);  
    if (shared_mem == NULL) {
        perror("Failed to attach to shared memory");
    } else {
        add_shared_memory_block(shared_mem, 0, key);
        printf("Attached shared memory segment with key %d at address %p\n", key, shared_mem);
    }
}
    else if (argc == 4 && strcmp(args[1], "-mmap") == 0) {
        char *file = args[2];
        char *perm = args[3];
        int protection = 0;
        if (strchr(perm, 'r') != NULL) protection |= PROT_READ;
        if (strchr(perm, 'w') != NULL) protection |= PROT_WRITE;
        if (strchr(perm, 'x') != NULL) protection |= PROT_EXEC;
        if (protection == 0) {
            printf("Invalid permissions. Please specify at least one of 'r', 'w', or 'x'.\n");
            break;
        }
        MemoryBlock *mapped_block = NULL;
        void *mapped_addr = map_file_to_memory(file, protection, &mapped_block);
        if (mapped_addr == NULL) {
            printf("Failed to map file: %s\n", file);
        }
    } 
    else {
        printf("Usage: allocate [-malloc <size>] | [-createshared <key> <size>] | [-shared <key>] | [-mmap <file> <perm>]\n");
    }
    break;
        case CMD_DEALLOCATE:
    if (argc == 3 && strcmp(args[1], "-malloc") == 0) {
        size_t size = (size_t)atoi(args[2]);
        deallocate_malloc(size);
    } else if (argc == 3 && strcmp(args[1], "-mmap") == 0) {
        char *file = args[2];
        deallocate_mmap(file);
    } else if (argc == 3 && strcmp(args[1], "-shared") == 0) {
        key_t key = (key_t)strtoul(args[2], NULL, 10);
        deallocate_shared(key);
    } else if (argc == 3 && strcmp(args[1], "-delkey") == 0) {
        key_t key = (key_t)strtoul(args[2], NULL, 10);
        deallocate_delkey(key);
    } else if (argc == 3 && strcmp(args[1], "addr") == 0) {
        void *addr = (void *)strtoul(args[2], NULL, 16);
        deallocate_addr(addr);
    } else {
        printf("Usage: deallocate -malloc <size> | -mmap <file> | -shared <key> | -delkey <key> | addr <address>\n");
    }
    break;
        case CMD_MEMFILL:
    if (argc == 5 && strcmp(args[1], "addr") == 0) {
        void *addr = (void *)strtoul(args[2], NULL, 16);
        size_t count = (size_t)atoi(args[3]);
        char ch = args[4][0];
        memfill(addr, count, ch);
    } else if (argc == 4) { 
        void *addr = (void *)strtoul(args[1], NULL, 16);
        size_t count = (size_t)atoi(args[2]);
        char ch = args[3][0];
        memfill(addr, count, ch);
    } else {
        printf("Usage: memfill <address> <count> <character>\n");
    }
    break;
    case CMD_MEMDUMP:
    if (argc == 4 && strcmp(args[1], "addr") == 0) {
        void *addr = (void *)strtoul(args[2], NULL, 16);  
        size_t count = (size_t)atoi(args[3]);  
        memdump(addr, count);  
    } else if (argc == 3) {  
        void *addr = (void *)strtoul(args[1], NULL, 16);  
        size_t count = (size_t)atoi(args[2]);  
        memdump(addr, count);  
    } else {
        printf("Usage: memdump <address> <count>\n");  
    }
    break;
    case CMD_MEMORY:
    if (argc == 2) {
        if (strcmp(args[1], "-funcs") == 0) {
            memory_funcs();  
        } else if (strcmp(args[1], "-vars") == 0) {
            memory_vars();   
        } else if (strcmp(args[1], "-blocks") == 0) {
            memory_blocks(); 
        } else if (strcmp(args[1], "-all") == 0) {
            memory_funcs();  
            memory_vars();   
            memory_blocks(); 
        } else if (strcmp(args[1], "-pmap") == 0) {
            get_pmap_output();
        } else {
            printf("Usage: memory -funcs, memory -vars, memory -blocks, memory -all, or memory -pmap\n");
        }
    } else {
        printf("Usage: memory -funcs, memory -vars, memory -blocks, memory -all, or memory -pmap\n");
    }
    break;
    case CMD_READFILE:
    if (argc == 4) {
        const char *file = args[1];
        void *addr = (void *)strtoul(args[2], NULL, 16); 
        size_t cont = (size_t)strtoul(args[3], NULL, 10); 
        read_file_to_memory(file, addr, cont);
    } else {
        printf("Usage: readfile file addr cont\n");
    }
    break;
    case CMD_WRITEFILE:
    if (argc == 4) {
        const char *file = args[1];
        const void *addr = (void *)strtoul(args[2], NULL, 16); 
        size_t cont = (size_t)strtoul(args[3], NULL, 10);      
        write_memory_to_file(file, addr, cont);
    } else {
        printf("Usage: writefile file addr cont\n");
    }
    break;
    case CMD_READ:
    if (argc == 4) {
        int fd = atoi(args[1]); 
        void *addr = (void *)strtoul(args[2], NULL, 16); 
        size_t cont = (size_t)strtoul(args[3], NULL, 10); 
        read_from_fd(fd, addr, cont);
    } else {
        printf("Usage: read df addr cont\n");
    }
    break;
    case CMD_WRITE:
    if (argc == 4) {
        int fd = atoi(args[1]); 
        const void *addr = (void *)strtoul(args[2], NULL, 16); 
        size_t cont = (size_t)strtoul(args[3], NULL, 10);      
        write_to_fd(fd, addr, cont);
    } else {
        printf("Usage: write df addr cont\n");
    }
    break;
    case CMD_RECURSE:
    if (argc == 2) {
        int n = atoi(args[1]); 
        recursive_function(n);
    } else {
        printf("Usage: recurse n\n");
    }
    break;
    case CMD_GETUID:
    if (argc == 1) {
        view_process_credentials();
    } else {
        printf("Usage: getuid\n");
    }
    break;
    case CMD_SETUID:
    if (argc == 2) {
        uid_t uid = (uid_t)atoi(args[1]); 
        if (setuid(uid) == 0) {
            printf("Effective UID set to: %u\n", uid);
        } else {
            perror("Error setting UID");
        }
    } else if (argc == 3 && strcmp(args[1], "-l") == 0) {
        uid_t uid = (uid_t)atoi(args[2]); 
        if (seteuid(uid) == 0) {
            printf("Effective UID set for login: %u\n", uid);
        } else {
            perror("Error setting effective UID for login");
        }
    } else {
        printf("Usage: setuid [-l] id\n");
    }
    break;
    case CMD_SHOWVAR:
    if (argc < 2) {
        printf("Uso: showvar v1 v2 ...\n");
    } else {
        show_variable_info(&args[1], argc - 1, envp); 
    }
    break;
    case CMD_CHANGEVAR:
    if (argc == 4) {
        change_variable(args[1], args[2], args[3], envp); 
    } else {
        printf("Usage: changevar [-a|-e|-p] var valor\n");
    }
    break;
    case CMD_SUBSVAR:
    if (argc == 5) {
        subsvar(argc, args, envp);
    } else {
        printf("Usage: subsvar [-a|-e] v1 v2 val\n");
    }
    break;
    case CMD_ENVIRON:
    if (argc == 2 && strcmp(args[1], "-addr") == 0) {
        show_environ_addresses(envp);  
    } else if (argc == 2 && strcmp(args[1], "-environ") == 0) {
        show_environ();
    } else {
        printf("Usage: environ [-environ|-addr]\n");
    }
    break;
    case CMD_FORK: {
    pid_t pid = fork(); 
    if (pid == 0) {
        printf("ejecutando proceso %d\n", getpid());
        exit(0); 
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    } else {
        perror("Fork failed");
    }
    break;
}
case CMD_SEARCH:
    if (argc == 1) { 
        displaySearchList();
    } else if (strcmp(args[1], "add") == 0 && argc == 3) {
        addDirectory(args[2]);
    } else if (strcmp(args[1], "del") == 0 && argc == 3) {
        deleteDirectory(args[2]);
    } else if (strcmp(args[1], "clear") == 0) {
        clearSearchList();
    } else if (strcmp(args[1], "path") == 0) {
        importPath();
    } else {
        printf("Invalid search command. Use: search [add|del|clear|path] [directory]\n");
    }
    break;
    case CMD_EXEC: {
    if (argc < 2) {
        printf("Usage: exec <env1=value1> ... <command> [args...]\n");
        break;
    }
    execCommand(args, envp);
    break;
}
case CMD_EXECPRI:
    if (argc < 3) {
        printf("Usage: execpri <priority> <program> [arguments...]\n");
    } else {
        execpriCommand(args, envp);
    }
    break;
   case CMD_FG:
    if (argc < 2) {
        printf("Usage: fg <program> [arguments...]\n");
    } else {
        fgCommand(&args[1]); 
    }
    break;
case CMD_FGPRI:
    if (argc < 3) {
        printf("Usage: fgpri <priority> <program> [arguments...]\n");
    } else {
        int priority = atoi(args[1]); 
        fgpri(&args[2], priority);    
    }
    break;
    case CMD_BACK:
    if (argc < 2) {
        printf("Usage: back prog args...\n");
    } else {
        backCommand(args); 
    }
    break;
    case CMD_BACKPRI:
    if (argc < 3) {
        printf("Usage: backpri <priority> <command> [args...]\n");
    } else {
        int priority = atoi(args[1]);
        backpri(&args[2], priority);
    }
    break;
    case CMD_LISTJOBS:
    if (argc == 1) {
        list_jobs(); 
    } else {
        printf("'listjobs' command does not accept any arguments.\n");
    }
    break;
    case CMD_DELJOBS:
    if (argc == 1) {
        deljobs(NULL);
    } else if (argc == 2) {
        if (strcmp(args[1], "-term") == 0 || strcmp(args[1], "-sig") == 0) {
            deljobs(args[1]);
        } else {
            printf("Usage: deljobs [-term|-sig]\n");
        }
    } else {
        printf("Usage: deljobs [-term|-sig]\n");
    }
    break;
case CMD_EXIT:
    if (argc == 1) {
        printf("Exiting shell. Goodbye!\n");
        freeList(openFiles);  
        exit(0);  
    } else {
        printf("'exit', 'quit', and 'bye' commands do not accept any arguments.\n");
    }
    break;
default:
    printf("Unknown command\n");
    break;
        case CMD_FORCE_DELETE:
            if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            delrec(args[i]);
            printf("%s deleted recursively\n", args[i]);
        }
    } else {
        printf("Usage: delrec <directory_path> [directory_path ...]\n");
    }
    break;
    }
}
int main(int argc, char *argv[], char *envp[]) {
    char input[1024];
    NodeList *openFiles = malloc(sizeof(NodeList));
    if (openFiles == NULL) {
        perror("Failed to allocate memory for openFiles");
        return 1;
    }
    openFiles->head = NULL;
    openFiles->tail = NULL;
    while (1) {
        printPrompt();
        readEntry(input, sizeof(input));
        processInput(input, openFiles, envp); 
    }
    freeList(openFiles);
    free(openFiles);
    return 0;
}
