/*
 * Copyright (c) 2013 Lawrence Livermore National Security. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdlib.h>
#include <infiniband/umad_str.h>

#define HEX(x)  ((x) < 10 ? '0' + (x) : 'a' + ((x) -10))
static void print_mad_hdr(FILE *file, uint8_t *p, size_t size)
{
	struct umad_hdr * umad_hdr = (struct umad_hdr *)p;
	uint8_t *cp = p;
	int i;
	char status_buf[256];

	fprintf(file, "%06d: ", 0);
	for (i = 0; i < size;) {
		fputc(HEX(*cp >> 4), file);
		fputc(HEX(*cp & 0xf), file);
		if (++i >= size)
			break;
		fputc(HEX(cp[1] >> 4), file);
		fputc(HEX(cp[1] & 0xf), file);
		if ((++i) % 4)
			fputc(' ', file);
		else {
			switch(i) {
				case 4:
					fprintf(file, "  %02d | %s | %02d | %s",
						umad_hdr->base_version,
						umad_class_str(umad_hdr->mgmt_class),
						umad_hdr->class_version,
						umad_method_str(umad_hdr->method));
					break;
				case 20:
					fprintf(file, "  %s | %s",
						umad_attribute_str(umad_hdr->mgmt_class,
							umad_hdr->attr_id),
						umad_mad_status_str(umad_hdr->status,
							status_buf, 256));
					break;
				case 24:
					fprintf(file, "  (AttributeModifier)");
					break;
				default:
					break;
			}
			fputc('\n', file);
			fprintf(file, "%06d: ", i);
		}
		cp += 2;
	}
	fputc('\n', file);
}

static void _xdump(FILE *file, uint8_t *p, size_t size, int width, int bits)
{
	uint8_t *cp = p;
	int i;

	fprintf(file, "%06d: ", 0);
	for (i = 0; i < size;) {
		fputc(HEX(*cp >> 4), file);
		fputc(HEX(*cp & 0xf), file);
		if (++i >= size)
			break;
		fputc(HEX(cp[1] >> 4), file);
		fputc(HEX(cp[1] & 0xf), file);
		if ((++i) % width)
			fputc(' ', file);
		else {
			fputc('\n', file);
			fprintf(file, "%06d: ", bits ? i*8 : i);
		}
		cp += 2;
	}
	fputc('\n', file);
}

size_t get_data_offset(uint8_t mgmt_class)
{
	switch (mgmt_class) {
		case UMAD_CLASS_SUBN_LID_ROUTED:
		case UMAD_CLASS_SUBN_DIRECTED_ROUTE:
		case UMAD_CLASS_PERF_MGMT:
		case UMAD_CLASS_BM:
		case UMAD_CLASS_DEVICE_MGMT:
		case UMAD_CLASS_SNMP:
		case UMAD_CLASS_DEVICE_ADM:
		case UMAD_CLASS_BIS:
		case UMAD_CLASS_BOOT_MGMT:
			return(64);
		case UMAD_CLASS_SUBN_ADM:
			return(56);
		case UMAD_CLASS_CM:
		case UMAD_CLASS_CONG_MGMT:
		default:
			return(24);
	}
	return (24);
}

void mad_dump(FILE * file, uint8_t *p, size_t size, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;
	size_t hdr_size;
	uint8_t class = p[1];
	size_t data_off = 24;

	if (msg) {
		va_start(va, msg);
		n = vsprintf(buf, msg, va);
		va_end(va);
		buf[n] = 0;
		fputs(buf, file);
	}

	data_off = get_data_offset(class);
	hdr_size = (size < data_off) ? size : data_off;

	print_mad_hdr(file, p, hdr_size);
	fprintf(file, "Data:\n");
	if ((size - hdr_size) > 0) {
		_xdump(file, p+hdr_size, size - hdr_size, 8, 1);
	}
}

void attr_dump(FILE * file, uint8_t *p, size_t size, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	if (msg) {
		va_start(va, msg);
		n = vsprintf(buf, msg, va);
		va_end(va);
		buf[n] = 0;
		fputs(buf, file);
	}

	_xdump(file, p, size, 8, 1);
}
