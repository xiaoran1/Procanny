#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <errno.h>
#include "memwatch.h"

static int pipenum = 0;
static int status;
static int myparentpid;
static int totalkill = 0;
static char *filename;
static int NameNum =0;
static char line[255];
static int pidnum = 0;
static int wtimemp = 0;
static char pidemp[28]= "";
static char nameemp[255]= "";
static char *logfilepath;
typedef struct {
    char ProcessName[255];
    char pidl[28];
    int  watime;
} MyPIDStruct;
typedef struct {
    char ProcessName[255];
    int  wtime;
} ConfigInfo;
typedef struct
{
   int fdp[2];   // 0 = read, 1 = write
   int fdc[2];
   int Childpid;
   int propid; 
   int available;
} Pipes;


static ConfigInfo *InfoStruct;
static MyPIDStruct *PidStruct;
static Pipes *PipeStruct;

void initPipeArray(){
    PipeStruct = (Pipes*) malloc(sizeof(Pipes)*128);
	for (int i=0;i<128;i++){		
		if(pipe(PipeStruct[i].fdp)<0){
			perror("log(-1) failed");
		}else{
			
			fcntl(PipeStruct[i].fdp[0], F_SETFL, O_NONBLOCK);
		}
		if(pipe(PipeStruct[i].fdc)<0){
			perror("log(-1) failed");
		}else{
			fcntl(PipeStruct[i].fdc[0], F_SETFL, O_NONBLOCK);
		}
		PipeStruct[i].Childpid=wtimemp;
		PipeStruct[i].propid = 0;
		PipeStruct[i].available = 0;
	}
}

void initialConfigInfo(){
    NameNum = 0;
	InfoStruct = (ConfigInfo*) malloc(sizeof(ConfigInfo)*128);
	for (int i=0;i<128;i++){
		InfoStruct[i].wtime=wtimemp;
		strcpy(InfoStruct[i].ProcessName,nameemp);
	}
}

void initialMyPIDStruct(){
	PidStruct = (MyPIDStruct*) malloc(sizeof(MyPIDStruct)*128);
	for (int i=0;i<128;i++){
		strcpy(PidStruct[i].pidl,pidemp);
		strcpy(PidStruct[i].ProcessName,nameemp);
		PidStruct[i].watime=wtimemp;
	}
}

void killotherprocanny(){
	 
	 myparentpid = getpid();
	 printf("parent pid %d\n",myparentpid);
	 FILE *fppro;
	 char procannypid[28];
	 char* grepComm;
	 grepComm = "pgrep procnanny";
	 if ((fppro = popen(grepComm, "r")) != NULL){
		 while((fgets(procannypid, sizeof(procannypid), fppro)) != NULL){
			 if(atoi(procannypid)!=myparentpid){
				 kill(atoi(procannypid), SIGKILL);
			 }
		 }
		 fclose(fppro);
	 }
}


void GetDataFromConfig(FILE *fp,ConfigInfo* InfoStruct){   
	 const char s[2] = " ";
	 char *token;
	 while((fgets(line, sizeof(line), fp)) != NULL){
	 	//get each line from the file as process names except the first line for maxtime
		token = strtok(line, s);
		strcpy(InfoStruct[NameNum].ProcessName,token);
		token = strtok(NULL, s);
		InfoStruct[NameNum].wtime = atoi(token);
		NameNum++;
	 }
	 fclose(fp);
}


void printmessage(int casenum, char processname[255], char pid[28], int totalnumkilled,int waittime,int parentpid){
	FILE *fp;
	fp=fopen(logfilepath, "a");
	if(fp == NULL){
	    exit(-1);
	}
    char buff[100];
    time_t now = time(0);
    strftime(buff, 100, "[%a %b %d %H:%M:%S MST %Y]", localtime (&now));
	switch (casenum){
		case 1:
			printf("%s Info: No '%s' processes found\n",buff,processname);
			fprintf(fp, "%s Info: No '%s' processes found\n",buff,processname);
			break;
		case 2:
			printf("%s Info: Initializing monitoring of process '%s' (PID %s).\n",buff,processname,pid);
			fprintf(fp, "%s Info: Initializing monitoring of process '%s' (PID %s).\n",buff,processname,pid);
			break;
		case 3:
			printf("%s Action: PID %s (%s) killed after exceeding %d seconds.\n",buff,pid,processname,waittime);
			fprintf(fp, "%s Action: PID %s (%s) killed after exceeding %d seconds.\n",buff,pid,processname,waittime);
			break;
		case 4:
			printf("%s Info: Caught SIGINT. Exiting cleanly. %d process(es) killed..\n",buff,totalnumkilled);
			fprintf(fp,"%s Info: Caught SIGINT. Exiting cleanly. %d process(es) killed..\n",buff,totalnumkilled);			
			break;	
		case 5:
			printf("%s Info: Caught SIGHUP. Configuration file '%s' re-read.\n",buff,filename);
			fprintf(fp,"%s Info: Caught SIGHUP. Configuration file '%s' re-read\n.",buff,filename);
			break;
		case 6:
			printf("%s Info: Parent process is PID %d\n",buff,parentpid);
			fprintf(fp,"%s Info: Parent process is PID %d\n",buff,parentpid);		
			break;
	}
	fclose(fp);
}


void Mymonitor(){	
	 pidnum = 0;
	 FILE *fpin;
	 int CheckNameExist = 0;
	 char grepcommand[255];	 
	 char pidline[28];
	 for(int j=0;j<NameNum;j++) {
		 CheckNameExist = 0;
		 strcpy(grepcommand,  "pgrep ");
		 strcat(grepcommand,InfoStruct[j].ProcessName);
		 if ((fpin = popen(grepcommand, "r")) == NULL){
			 printf("popen error\n");
	 	 }else{
	 		 while((fgets(pidline, sizeof(pidline), fpin)) != NULL){
	 			strcpy(PidStruct[pidnum].pidl,pidline);
	 			strcpy(PidStruct[pidnum].ProcessName,InfoStruct[j].ProcessName);
	 			PidStruct[pidnum].watime = InfoStruct[j].wtime;
	 			//printmessage(2,InfoStruct[j].ProcessName,pidline,0,0);	 				 				 						 				
	 			pidnum++;
	 			CheckNameExist = 1;
	 		 }
	 		 if(CheckNameExist == 0){
	 			printmessage(1,InfoStruct[j].ProcessName,pidemp,0,0,0);
	 		 } 		
	 	 }
		 fclose(fpin);
	 }
}


void Running(){	
	//MyPIDStruct tempstruct;
	int n = 0;
	int w = 0;
	int pid; 
	int noemptypipe=11;//11 represent there's an old child available to accept new process, which means no need to fork new child in this round
	int pipenotosend = 0;
	int oldchildavailable = 0;
	for(int i=0;i<pidnum;i++){		
		oldchildavailable = 0;
		noemptypipe = 0;
		//printf("pipenum is %d\n",pipenum);
		for(int pi=0;pi<pipenum;pi++){	

			if(PipeStruct[pi].available == 0){
				close(PipeStruct[pi].fdc[1]);		
				n=read(PipeStruct[pi].fdc[0], &noemptypipe, sizeof(noemptypipe));
				if(n!=-1){
					PipeStruct[pi].propid = 0;
					PipeStruct[pi].available=1;
					if(oldchildavailable == 0){	
						pipenotosend = pi;
						oldchildavailable=1;
					}
				}
			}else{
				if(oldchildavailable == 0){	
					pipenotosend = pi;
					oldchildavailable=1;
				}
			}
			if(PipeStruct[pi].propid == atoi(PidStruct[i].pidl)){
				// if the new pid has been monitored already and the corresponding process still sleep
				noemptypipe = 11;
				oldchildavailable=0;
				break;
			}			
		}
		//if there's an old child available and the new pid has not been monitored previously
		if(oldchildavailable==1){
			close(PipeStruct[pipenotosend].fdp[0]);				
			write(PipeStruct[pipenotosend].fdp[1],&PidStruct[i] , sizeof(PidStruct[i]));
			n=read(PipeStruct[pipenotosend].fdc[0], &noemptypipe, sizeof(noemptypipe));
			while(n<0){
				close(PipeStruct[pipenotosend].fdc[1]);		
				n=read(PipeStruct[pipenotosend].fdc[0], &noemptypipe, sizeof(noemptypipe));
			}
			PipeStruct[pipenotosend].propid = noemptypipe;
			PipeStruct[pipenotosend].available = 0;
			noemptypipe=11;
		}
		if(pipenum == 0 || noemptypipe != 11){
			pipenum++;	
			if ((pid = fork()) < 0) {
				printf("%s","fork error");
			}else if (pid>0){
			//parent start================================================
				PipeStruct[pipenum-1].Childpid = pid;
				close(PipeStruct[pipenum-1].fdp[0]);
				w = write(PipeStruct[pipenum-1].fdp[1],&PidStruct[i] , sizeof(PidStruct[i]));	
				//printf("w is %d the pipenum  %d pid is %d value %d time %d\n",w,pipenum,pid,atoi(PidStruct[i].pidl),PidStruct[i].watime);
				if(w<0){
					perror("signal");
				}
				while(n<=0){
					close(PipeStruct[pipenum-1].fdc[1]);		
					n=read(PipeStruct[pipenum-1].fdc[0], &noemptypipe, sizeof(noemptypipe));				
				}	
				PipeStruct[pipenum-1].propid = noemptypipe;
				PipeStruct[pipenum-1].available = 0;
			}else {	
			//child start================================================			
				int killreturn = 0;
				int noemptypipe2 = 11;
				for(;;){
					//read from pipe start=============================================
					MyPIDStruct tempstruct;
					close(PipeStruct[pipenum-1].fdp[1]);					
					n = read(PipeStruct[pipenum-1].fdp[0],&tempstruct, sizeof(tempstruct));
					if(n>0){
					//read from pipe end===============================================
						//send to parent a info that I'm full already
						noemptypipe2 = atoi(tempstruct.pidl);					
						close(PipeStruct[pipenum-1].fdc[0]);
						write(PipeStruct[pipenum-1].fdc[1],&noemptypipe2, sizeof(noemptypipe2));
						//==================================print message
						killreturn = 0;
						printmessage(2,tempstruct.ProcessName,tempstruct.pidl,0,0,0);
					//	printmessage(6,nameemp,pidemp,0,0,getpid());	
						sleep(tempstruct.watime);
						//==================================done kill
						killreturn = kill(atoi(tempstruct.pidl), SIGKILL);
						if(killreturn==0){								
							printmessage(3,tempstruct.ProcessName,tempstruct.pidl,0,tempstruct.watime,0);		
							totalkill++;
						}
						//send to parent a info that I'm able to take the job to monitor the new process	
						noemptypipe2 = 11;
						//printf("child %d get release send through pipe %d with %d\n",getpid(), pipenum-1,noemptypipe2);
						close(PipeStruct[pipenum-1].fdc[0]);
						write(PipeStruct[pipenum-1].fdc[1],&noemptypipe2, sizeof(noemptypipe2));
						//printf("===========child %d get pipe %d\n",getpid(), pipenum-1);
						
					}
				}
			}
			//child end=================================================
		}	
		//forloop end=============================================
	}
}



void handle_signal(int signal) {
    // Find out which signal we're handling
    switch (signal) {
        case SIGHUP:
            //--------------------------------
        	;
        	if(getpid()==myparentpid){
				FILE *fp = fopen(filename,"r");  
				NameNum = 0;
				for (int i=0;i<sizeof(InfoStruct);i++){
					InfoStruct[i].wtime=wtimemp;
					strcpy(InfoStruct[i].ProcessName,nameemp);
				}
				GetDataFromConfig(fp,InfoStruct);
				printmessage(5,nameemp,pidemp,0,0,0);  
				/*
				for (int i=0;i<sizeof(PidStruct);i++){
					strcpy(PidStruct[i].pidl,pidemp);
					strcpy(PidStruct[i].ProcessName,nameemp);
					PidStruct[i].watime=wtimemp;
				}
				
				Mymonitor();
				*/
				//Running();
				//--------------------------------
        	}
            break;
        case SIGINT:
        	;
        	if(getpid()==myparentpid){
        		while(wait(&status)>0){	
        			totalkill+=WEXITSTATUS(status);			
        		}
            	printmessage(4,nameemp,pidemp,totalkill,0,0);
				free(PidStruct);
				free(InfoStruct);
				free(PipeStruct);
				exit(0);
        	}else{
        		free(PidStruct);
        		free(InfoStruct);
        		free(PipeStruct);
				exit(totalkill);
        	}
        	break;
        default:
            fprintf(stderr, "Caught wrong signal: %d\n", signal);
            return;
    }
}

int main(int argc, char* argv[]){
	killotherprocanny();
	free(PipeStruct);
	initPipeArray();
	filename = argv[1];    
    signal(SIGHUP, handle_signal);	
    signal(SIGINT, handle_signal);
	char* envariable;
	envariable = getenv("PROCNANNYLOGS");	;
	//----------------------------------------------------------
	FILE *flogfile;
	logfilepath = envariable;
	flogfile=fopen(logfilepath, "w");
	if(flogfile == NULL){
		exit(-1);
	}
	fclose(flogfile);	
    FILE *fp = fopen(filename,"r");
    //open the config file and read
    if(fp!=NULL) { 
    	initialConfigInfo();
    	GetDataFromConfig(fp,InfoStruct);    	
    	//create pid structure to store all the pid that pgrep get
    	initialMyPIDStruct();
    	printmessage(6,nameemp,pidemp,0,0,getpid());	
    	Mymonitor();    	 		
    	//---------------------------------------------------------------------------------
    	printf("||-------------------------------------------------------------------||\n"); 	
    	Running();
    }else{
    	printf("this file doesn't exist\n");
    }
    for(;;){
		sleep(5);
		printf("||-------------------------------------------------------------------||\n"); 	
		for (int i=0;i<sizeof(PidStruct);i++){
			strcpy(PidStruct[i].pidl,pidemp);
			strcpy(PidStruct[i].ProcessName,nameemp);
			PidStruct[i].watime=wtimemp;
		}
		Mymonitor();
		Running();
    }
    exit(0);
}


 
