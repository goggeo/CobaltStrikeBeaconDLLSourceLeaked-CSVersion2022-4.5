#include <Windows.h>
#include <stdio.h>
#include "bformat.h"
#include <WinSock2.h>

/* initialize this formatted text buffer */
void bformat_init(formatp * buffer, int maxsz) {
	char * data = (char *)malloc(maxsz);
	bformat_existing(buffer, data, maxsz);
}

/* create a formatted text buffer on top of an existing buffer */
void bformat_existing(formatp * buffer, char * data, int maxsz) {
	buffer->original = data;
	buffer->self = buffer->original;
	buffer->length = 0;
	buffer->size = maxsz;

	memset(buffer->original, 0, maxsz);
}

/* reset this back to our original parameters to make re-use possible */
void bformat_reset(formatp * buffer) {
	buffer->self = buffer->original;
	buffer->length = 0;
	memset(buffer->original, 0, buffer->length);
}

/* add an integer to our bformat data */
void bformat_int(formatp * buffer, int value) {
	value = htonl(value);
	bformat_copy(buffer, (char *)&value, 4);
}

/* copy some value into our buffer */
void bformat_copy(formatp * buffer, char * src, int length) {
	if (length >= (buffer->size - buffer->length) || length == 0)
		return;

	memcpy(buffer->self, src, length);

	buffer->self   += length;
	buffer->length += length;
}

/* format some text into our buffer and append it */
void bformat_printf(formatp * buffer, char * fmt, ...) {
	INT32   est;
	INT32   read;
	va_list va;

	/* how much data do we expect to stuff into this buffer? */
	va_start(va, fmt);
	est = _vscprintf(fmt, va);
	va_end(va);

	/* let's sanity check the data */
	if (est <= 0 || est >= (buffer->size - buffer->length)) {
		return;
	}

	/* populate the data structure */
	va_start(va, fmt);
	read = vsprintf_s(buffer->self, buffer->size - buffer->length, fmt, va);
	va_end(va);

	/* update our values */
	buffer->self   += read;
	buffer->length += read;
}

/* free this buffer and make it forensically clean */
void bformat_free(formatp * buffer) {
	memset(buffer->original, 0, buffer->size);
	free(buffer->original);
}

/* return a pointer to the string managed by this buffer */
char * bformat_string(formatp * buffer) {
	return buffer->original;
}

/* return the length of the string in this buffer */
DWORD bformat_length(formatp * buffer) {
	return buffer->length;
}

char * bformat_tostring(formatp * buffer, int * size) {
	DWORD len = bformat_length(buffer);
	if (size != NULL)
		*size = (int)len;

	if (size == 0)
		return NULL;

	return bformat_string(buffer);
}
