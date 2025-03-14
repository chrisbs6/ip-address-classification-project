/* -*-  Mode:C++; c-basic-offset:4; tab-width:8; indent-tabs-mode:nil -*- */
/*
 * Copyright (C) 2004-2010 by the University of Southern California
 * $Id: icmptrain_datafile.hh 18755 2013-10-24 23:47:02Z yuri $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef ICMPTRAIN_DATAFILE_H
#define ICMPTRAIN_DATAFILE_H

__BEGIN_DECLS

#define IPR_TYPE_NONE			0x0
#define IPR_TYPE_DATAv1			0x1  /* XXX deprecated in future use */
#define IPR_TYPE_TXT_v1			0x2  /* XXX deprecated in future use */
#define IPR_TYPE_DATAv2			0x3
#define IPR_TYPE_TXT_v2			0x4  /* special text record type, describing format */
#define IPR_TYPE_DATAv3			0x5  /* only interpretation of fields slightly changed from v2 */
#define IPR_TYPE_TXT_v3			0x6  /* same as v2 */

#define IPR_REPLY_NOREPLY		0xff /* reserved per RFC 792 */
#define IPR_REPLY_MKREPLY(type, code)	(((type) << 4) | (code))

#define IPR_TYPE_DATAv1_LEN		sizeof(icmptrain_probe_record_datav1_t)
#define IPR_TYPE_DATAv2_LEN		sizeof(icmptrain_probe_record_datav2_t)
#define IPR_TYPE_DATAv3_LEN		sizeof(icmptrain_probe_record_datav3_t)
#define IPR_TYPE_TXT_v1_LEN		255
#define IPR_TYPE_TXT_v2_LEN		sizeof(icmptrain_probe_record_datav2_t) /* same as data */
#define IPR_TYPE_TXT_v3_LEN		sizeof(icmptrain_probe_record_datav3_t) /* same as data */

#ifndef MIN
#define MIN(a,b)			((a) < (b) ? (a) : (b))
#endif /* !MIN() */
#ifndef ABS
#define ABS(a)				((a) < 0 ? -(a) : (a))
#endif /* !ABS() */

#define IPR_LEN_MIN			MIN(IPR_TYPE_DATAv1_LEN, IPR_TYPE_TXT_v1_LEN)
#define IPR_LEN_MAX			255

#ifndef lint
static const char icmptrain_datafile_h_id[] =
    "@(#) $Id: icmptrain_datafile.hh 18755 2013-10-24 23:47:02Z yuri $\n";
static inline const char* icmptrain_datafile_hdr_vers(void) { return icmptrain_datafile_h_id; }
#endif

/* XXX This is deprecated (but backward-compatible) as of version 2666 */
typedef struct icmptrain_probe_record_datav1_ {
    /* all fields in network byte order */
    uint8_t	ipr_type;	/* record type   = IPR_TYPE_DATAv1 */
    uint8_t	ipr_len;	/* record length = IPR_TYPE_DATAv1_LEN */
    uint8_t	ipr_reply_type;	/* reply type (or IPR_REPLY_NOREPLY) */
    uint8_t	ipr_ttl;	/* remaining ttl of the response */
    uint32_t	ipr_time_s;	/* sent (if not available, received) seconds since the Epoch */
    uint32_t	ipr_rtt_us;	/* us */
    uint32_t	ipr_probe_addr;	/* probed address */
    uint32_t	ipr_reply_addr;	/* if different from probe_addr, or 0 */
} icmptrain_probe_record_datav1_t;

#define IPR_FLAG_DUMPED		0x01
#define IPR_FLAG_MATCH_RH	0x02
#define IPR_FLAG_MATCH_SRC	0x04
#define IPR_FLAG_COOKIE1	0x08
#define IPR_FLAG_COOKIE2	0x10

//COOKIE2, COOKIE1: 00
inline uint8_t set_cookie_notried(uint8_t flags) { 
    return flags & ~(IPR_FLAG_COOKIE2|IPR_FLAG_COOKIE1); 
}
//COOKIE2, COOKIE1: 11   
inline uint8_t set_cookie_tried_matched(uint8_t flags) {
    return flags | (IPR_FLAG_COOKIE2|IPR_FLAG_COOKIE1);
}
//COOKIE2, COOKIE1: 10
inline uint8_t set_cookie_tried_notmatched(uint8_t flags) {
    return (flags | IPR_FLAG_COOKIE2) & ~IPR_FLAG_COOKIE1;
}
//COOKIE2, COOKIE1: 01
inline uint8_t set_cookie_tried_notreturned(uint8_t flags) {
    return (flags & ~IPR_FLAG_COOKIE2) | IPR_FLAG_COOKIE1;
}

/* Current record */
typedef struct icmptrain_probe_record_datav2_ {
    /* all fields in network byte order */
    uint8_t	ipr_type;	/* record type   = IPR_TYPE_DATAv2 */
    uint8_t	ipr_len;	/* record length = IPR_TYPE_DATAv2_LEN */
    uint8_t	ipr_reply_type;	/* icmp reply type (or IPR_REPLY_NOREPLY)  XXX pointer to RFC */
    uint8_t	ipr_reply_code; /* icmp reply code XXX pointer to RFC */
    uint16_t	ipr_zero16;	/* unused */
    uint8_t     ipr_flags;	/* flags defined above as IPR_FLAG_* */	
    uint8_t	ipr_ttl;	/* remaining ttl of the response (hops) */
    uint32_t	ipr_time_s;	/* sent (if not available, received) seconds since the Epoch */
    uint32_t	ipr_rtt_us;	/* RTT in microseconds */
    uint32_t	ipr_probe_addr;	/* probed address */
    uint32_t	ipr_reply_addr;	/* if different from probe_addr, or 0 */
} icmptrain_probe_record_datav2_t;

typedef icmptrain_probe_record_datav2_t icmptrain_probe_record_datav3_t;

typedef struct icmptrain_probe_record_txt_v1_ {
    uint8_t	ipr_type;	/* = IPR_TYPE_TXT_v1 */ 
    uint8_t	ipr_len;	/* = IPR_TYPE_TXT_v1_LEN */
#define IPR_MSG_TXT_v1_MAX	(IPR_TYPE_TXT_v1_LEN-2)
    char	ipr_msg[IPR_MSG_TXT_v1_MAX];
} icmptrain_probe_record_txt_v1_t;

typedef struct icmptrain_probe_record_txt_v2_ {
    uint8_t	ipr_type;	/* = IPR_TYPE_TXT_v2 */ 
    uint8_t	ipr_len;	/* = IPR_TYPE_TXT_v2_LEN */
#define IPR_MSG_TXT_v2_MAX	(IPR_TYPE_TXT_v2_LEN-2)
    char	ipr_msg[IPR_MSG_TXT_v2_MAX];
} icmptrain_probe_record_txt_v2_t;

#define IPR_MSG_TXT_v3_MAX	(IPR_TYPE_TXT_v3_LEN-2)
typedef icmptrain_probe_record_txt_v2_t icmptrain_probe_record_txt_v3_t;

typedef enum {
    IPR_RET_OK		= 0,
    IPR_RET_EOF		= -1,
    IPR_RET_SHORTBUF	= -2,
    IPR_RET_FILE_ERROR 	= -3,
    IPR_RET_BADTYPE	= -4,
    IPR_RET_BADLEN	= -5,
    IPR_RET_ZLIB_ERROR	= -6,
    IPR_RET_BZLIB_ERROR	= -7
} ipr_ret_t;

typedef enum {
    IPR_COMPRESS_NONE	= 0,
    IPR_COMPRESS_ZLIB	= 1,
    IPR_COMPRESS_BZIP2	= 2
} ipr_compress_t;

/* hide use of zlib in the file abstraction */
typedef struct icmptrain_file_t {
    void *		_fp;		/* either gzlib file pointer or FILE * */
    FILE *		_file;		/* original file */
    ipr_compress_t	_compression;	/* one of the above enum */
    uint64_t		_pos;		/* read/written bytes */
    uint64_t		_ckpt_pos;	/* last checkpointed _pos */
} icmptrain_file_t;

/* data driven checkpointing */
typedef void 	(*checkpoint_callback_t)();
void			set_checkpoint_callback(checkpoint_callback_t, uint64_t);
/* read one record to the buf, in network byte order */
ipr_ret_t		icmptrain_read(icmptrain_file_t *, void *, size_t);
/* write a text record (usually at the beginning of a file) (deprecated in future use) */
ipr_ret_t		icmptrain_write_txt_v1(icmptrain_file_t *, const char *, size_t);
/* write a text record (usually at the beginning of a file) (deprecated in future use) */
ipr_ret_t		icmptrain_write_txt_v2(icmptrain_file_t *, const char *, size_t);
/* write a text record (usually at the beginning of a file) (deprecated in future use) */
ipr_ret_t		icmptrain_write_txt_v3(icmptrain_file_t *, const char *, size_t);
/* write out data record v1 (deprecated in future use) */
ipr_ret_t		icmptrain_write_data_v1(icmptrain_file_t *, icmptrain_probe_record_datav1_t *);
/* write out data record v2 */
ipr_ret_t		icmptrain_write_data_v2(icmptrain_file_t *, icmptrain_probe_record_datav2_t *);
/* write out data record v3 */
ipr_ret_t		icmptrain_write_data_v3(icmptrain_file_t *, icmptrain_probe_record_datav2_t *);
/* remap the file */
icmptrain_file_t *	icmptrain_remap(FILE *, const char *, ipr_compress_t);
/* flush the file */
ipr_ret_t		icmptrain_flush(icmptrain_file_t *);
/* close the file */
ipr_ret_t		icmptrain_close(icmptrain_file_t *);
/* current offset */
uint64_t		icmptrain_tell(icmptrain_file_t *);
/* seek */
ipr_ret_t		icmptrain_seek(icmptrain_file_t *, int64_t, int);
/* skip forward */
ipr_ret_t		icmptrain_skip(icmptrain_file_t *, uint64_t);			
__END_DECLS

#endif /* ICMPTRAIN_DATAFILE_H */
