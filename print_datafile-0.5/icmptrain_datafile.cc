/* -*-  Mode:C++; c-basic-offset:4; tab-width:8; indent-tabs-mode:nil -*- */
/*
 * Copyright (C) 2004-2012 by the University of Southern California
 * $Id: icmptrain_datafile.cc 20373 2014-04-07 17:19:52Z yuri $
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

#ifndef lint
static const char rcsid[] =
   "@(#) $Id: icmptrain_datafile.cc 20373 2014-04-07 17:19:52Z yuri $";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif //HAVE_CONFIG_H

#include <netinet/in.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif /* HAVE_ZLIB_H */

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif /* HAVE_BZLIB_H */

#include <climits>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <iostream>
#include <iomanip>

#include "icmptrain_datafile.hh"

using namespace std;


#ifndef HAVE_ZLIB_H
static void
zlib_not_compiled(void)
{
    cerr << "icmptrain_datafile isn't compiled with gzip support\n";
    ::exit(1);
}
#endif /* !HAVE_ZLIB_H */
#ifndef HAVE_BZLIB_H
static void
bzlib_not_compiled(void)
{
    cerr << "icmptrain_datafile isn't compiled with bz2 support\n";
    ::exit(1);
}
#endif /* !HAVE_BZLIB_H */

/* data-driven checkpointing */
static checkpoint_callback_t _checkpoint_callback = NULL;
static uint64_t 	     _checkpoint_bytes    = 0;

/* static/inline functions */
inline ipr_ret_t
_icmptrain_write(icmptrain_file_t *file, const void *buf, size_t buf_len) {
    if (!file) return IPR_RET_OK;
    int errnum;
    switch(file->_compression) {
    case IPR_COMPRESS_ZLIB: 
	{
#ifdef HAVE_ZLIB_H
	    gzFile gz = reinterpret_cast<gzFile>(file->_fp);
	    if (gzwrite(gz, const_cast<void *>(buf), buf_len) 
		!= static_cast<int>(buf_len)) {
		const char *error = gzerror(gz, &errnum);
		if (errnum != Z_ERRNO) {
		    cerr << "zlib error: " << error << endl;
		    return IPR_RET_ZLIB_ERROR;
		}
		return IPR_RET_FILE_ERROR;
	    }
#else
	    zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	    break;
	}
    case IPR_COMPRESS_BZIP2:
#ifdef HAVE_BZLIB_H
	if (BZ2_bzwrite(file->_fp, const_cast<void*>(buf), buf_len) != (int)buf_len) {
	    const char *error = BZ2_bzerror(file->_fp, &errnum);
	    cerr << "bzlib error: " << error << endl;
	    return IPR_RET_BZLIB_ERROR;
	}
#else
	bzlib_not_compiled();
#endif /* HAVE_BZLIB_H */
	break;

    case IPR_COMPRESS_NONE:
	if (fwrite(buf, 1, buf_len, (FILE*)file->_fp) != buf_len) {
	    errno = ferror((FILE*)file->_fp);
	    return IPR_RET_FILE_ERROR;
	}
	break;
    }
    file->_pos += buf_len;

    if (_checkpoint_callback && 
	(file->_pos - file->_ckpt_pos > _checkpoint_bytes)) {
	//temporary zero out callback to avoid infinite recursion
	const checkpoint_callback_t callback = _checkpoint_callback;
	_checkpoint_callback = NULL;
	callback();
	//restore callback
	_checkpoint_callback = callback;
	file->_ckpt_pos = file->_pos;
    }
    return IPR_RET_OK;
}

inline ipr_ret_t
_icmptrain_read(icmptrain_file_t *file, void *buf, size_t *buf_len) {
    size_t len = 0;
    int errnum;
    const char *err;
    switch (file->_compression) {
    case IPR_COMPRESS_ZLIB: 
	{
#ifdef HAVE_ZLIB_H
	    gzFile gz = reinterpret_cast<gzFile>(file->_fp);
	    len = gzread(gz, buf, *buf_len);
	    
	    if (len == *buf_len)
		break;
	    if (len == 0)
		return IPR_RET_EOF;
	    if ((int)len == -1) {
		err = gzerror(gz, &errnum);
		cerr << "zlib error: " << err << endl;
		if (errno == Z_ERRNO)
		    ::perror("ERRNO:");
		return IPR_RET_ZLIB_ERROR;
	    }
	    cerr << "input file is too short: " << len << "\n";
	    return IPR_RET_FILE_ERROR;
#else
	    zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	    break;
	}
    case IPR_COMPRESS_BZIP2:
#ifdef HAVE_BZLIB_H
	len = BZ2_bzread(file->_fp, buf, *buf_len);
	if (len == *buf_len)
	    break;
	if (len == 0) {
	    int32_t nUnused = -1, bzerr;
	    void    *unusedTmpV;
	    BZ2_bzReadGetUnused(&bzerr, file->_fp, &unusedTmpV, &nUnused);

	    if (fgetc(file->_file) == EOF && nUnused == 0)
		return IPR_RET_EOF;
	    cerr << "WARNING: detected file corruption or concatenated bzip\n"
		 << "  this utility cannot yet handle concat bzip files.\n";
	    return IPR_RET_BZLIB_ERROR;
	}
	if ((int)len == -1) {
	    err = BZ2_bzerror(file->_fp, &errnum);
	    cerr << "bzlib error: " << err << endl;
	    return IPR_RET_BZLIB_ERROR;
	}
	cerr << "input file is too short: " << len << "\n";
	return IPR_RET_FILE_ERROR;
#else
	bzlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;

    case IPR_COMPRESS_NONE:
	len = fread(buf, 1, *buf_len, (FILE*)file->_fp);

	if (len == *buf_len)
	    break;
	if ((errno = ferror((FILE*)file->_fp)) != 0) {
	    cerr << "input file is too short: " << len << "\n";
	    ::perror("ERRNO:");
	    return IPR_RET_FILE_ERROR;
	} else
	    return IPR_RET_EOF;
    default:
	cerr << "unknown compression type\n";
	return IPR_RET_BADTYPE;
    }
    file->_pos += (uint64_t)len; /* update offset */
    return IPR_RET_OK;
}

/* request checkpointing every recs written records */
void 
set_checkpoint_callback(checkpoint_callback_t callback, uint64_t bytes)
{
    _checkpoint_callback = callback;
    _checkpoint_bytes	 = bytes;
}

ipr_ret_t
icmptrain_write_txt_v1(icmptrain_file_t *file, const char *msg, size_t msg_len) 
{
    icmptrain_probe_record_txt_v1_t textrec;

    if (msg_len > sizeof(textrec.ipr_msg))
	return IPR_RET_SHORTBUF;

    memset(&textrec, 0, sizeof(textrec));
    textrec.ipr_type = IPR_TYPE_TXT_v1;
    textrec.ipr_len = (u_char)IPR_TYPE_TXT_v1_LEN;
    memcpy(&textrec.ipr_msg, msg, msg_len);
    return _icmptrain_write(file, &textrec, IPR_TYPE_TXT_v1_LEN);
}

ipr_ret_t
icmptrain_write_txt_v2(icmptrain_file_t *file, const char *msg, size_t msg_len) 
{
    icmptrain_probe_record_txt_v2_t textrec;
    const char *cp = msg;
    while (msg_len > 0) {
	memset(&textrec, 0, sizeof(textrec));
	textrec.ipr_type = IPR_TYPE_TXT_v2;
	textrec.ipr_len = (u_char)IPR_TYPE_TXT_v2_LEN;
	size_t len = (msg_len < IPR_MSG_TXT_v2_MAX) ? msg_len : IPR_MSG_TXT_v2_MAX;

	memcpy(&textrec.ipr_msg, cp, len);
	cp += len;

	ipr_ret_t ret = _icmptrain_write(file, &textrec, IPR_TYPE_TXT_v2_LEN);
	if (ret != IPR_RET_OK)
	    return ret;

	assert(msg_len >= len);
	msg_len -= len;
    }
    return IPR_RET_OK;
}

ipr_ret_t
icmptrain_write_txt_v3(icmptrain_file_t *file, const char *msg, size_t msg_len) 
{
    icmptrain_probe_record_txt_v3_t textrec;
    const char *cp = msg;
    while (msg_len > 0) {
	memset(&textrec, 0, sizeof(textrec));
	textrec.ipr_type = IPR_TYPE_TXT_v3;
	textrec.ipr_len = (u_char)IPR_TYPE_TXT_v3_LEN;
	size_t len = (msg_len < IPR_MSG_TXT_v3_MAX) ? msg_len : IPR_MSG_TXT_v3_MAX;

	memcpy(&textrec.ipr_msg, cp, len);
	cp += len;

	ipr_ret_t ret = _icmptrain_write(file, &textrec, IPR_TYPE_TXT_v3_LEN);
	if (ret != IPR_RET_OK)
	    return ret;

	assert(msg_len >= len);
	msg_len -= len;
    }
    return IPR_RET_OK;
}

/* read one record to the buf */
ipr_ret_t
icmptrain_read(icmptrain_file_t *file, void *record_buf, size_t buf_len)
{
    size_t len = IPR_LEN_MIN;
    icmptrain_probe_record_datav1_t *rec;
    
    if (buf_len < IPR_LEN_MIN)
	return IPR_RET_SHORTBUF;

    ipr_ret_t ret = _icmptrain_read(file, record_buf, &len);
    
    if (ret != IPR_RET_OK)
	return ret;

    rec = (icmptrain_probe_record_datav1_t *)record_buf;
    switch (rec->ipr_type) {
    case IPR_TYPE_DATAv1:
	if (rec->ipr_len != IPR_TYPE_DATAv1_LEN) {
	    cerr << "Bad record (type: DATAv1) length";
	    ret = IPR_RET_BADLEN;
	}
	break;
    case IPR_TYPE_TXT_v1:
	if (rec->ipr_len != IPR_TYPE_TXT_v1_LEN) {
	    cerr << "Bad record (type: TXT_v1) length";
	    ret =IPR_RET_BADLEN;
	}
	break;
    case IPR_TYPE_DATAv2:
	if (rec->ipr_len != IPR_TYPE_DATAv2_LEN) {
	    cerr << "Bad record (type: DATAv2) length";
	    ret = IPR_RET_BADLEN;
	}
	break;
    case IPR_TYPE_TXT_v2:
	if (rec->ipr_len != IPR_TYPE_TXT_v2_LEN) {
	    cerr << "Bad record (type: TXT_v2) length";
	    ret =IPR_RET_BADLEN;
	}
	break;
    case IPR_TYPE_DATAv3:
	if (rec->ipr_len != IPR_TYPE_DATAv3_LEN) {
	    cerr << "Bad record (type: DATAv3) length";
	    ret = IPR_RET_BADLEN;
	}
	break;
    case IPR_TYPE_TXT_v3:
	if (rec->ipr_len != IPR_TYPE_TXT_v3_LEN) {
	    cerr << "Bad record (type: TXT_v3) length";
	    ret =IPR_RET_BADLEN;
	}
	break;
    default:
	cerr << "Bad record type: 0x" << hex << rec->ipr_type;
	ret = IPR_RET_BADTYPE;
    }
    if (rec->ipr_len > buf_len)
	ret = IPR_RET_SHORTBUF;

    if (ret != IPR_RET_OK) {
	cerr << " @offset = " << file->_pos << endl;
	return ret;
    }

    if (rec->ipr_len > IPR_LEN_MIN) {
	/* need to read the remainder */
	len = rec->ipr_len - IPR_LEN_MIN;
	ret = _icmptrain_read(file, (u_char *)record_buf + IPR_LEN_MIN, &len);
	if (ret != IPR_RET_OK) {
	    if (ret == IPR_RET_EOF) {
		cerr << "premature end of file\n";
		return ret;
	    }
	}
    }
    /* XXX convert something to host byte order? */
    return IPR_RET_OK;
}

ipr_ret_t	
icmptrain_write_data_v1(icmptrain_file_t *file, icmptrain_probe_record_datav1_t *rec)
{
    rec->ipr_type = IPR_TYPE_DATAv1;
    rec->ipr_len  = IPR_TYPE_DATAv1_LEN;
    
    return _icmptrain_write(file, rec, IPR_TYPE_DATAv1_LEN);
}

ipr_ret_t	
icmptrain_write_data_v2(icmptrain_file_t *file, icmptrain_probe_record_datav2_t *rec)
{
    rec->ipr_type = IPR_TYPE_DATAv2;
    rec->ipr_len  = IPR_TYPE_DATAv2_LEN;

    return _icmptrain_write(file, rec, IPR_TYPE_DATAv2_LEN);
}

ipr_ret_t	
icmptrain_write_data_v3(icmptrain_file_t *file, icmptrain_probe_record_datav3_t *rec)
{
    rec->ipr_type = IPR_TYPE_DATAv3;
    rec->ipr_len  = IPR_TYPE_DATAv3_LEN;

    return _icmptrain_write(file, rec, IPR_TYPE_DATAv3_LEN);
}

icmptrain_file_t *
icmptrain_remap(FILE *file, const char *mode, ipr_compress_t compression)
{
    icmptrain_file_t *f = (icmptrain_file_t *)malloc(sizeof(icmptrain_file_t));
    
    if (f == NULL) {
	cerr << "out of memory\n";
	return NULL;
    }
    f->_pos = 0;
    f->_ckpt_pos = 0;
    f->_compression = compression;
    f->_file = file;

    switch (compression) {
    case IPR_COMPRESS_ZLIB:
#ifdef HAVE_ZLIB_H
	if ((f->_fp = gzdopen(::fileno(file), mode)) == NULL) {
	    cerr <<"gzdopen:insufficient memory for compression state\n";
	    free(f);
	    return NULL;
	}
#else
	zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;
    case IPR_COMPRESS_BZIP2:
#ifdef HAVE_BZLIB_H
	if ((f->_fp = BZ2_bzdopen(::fileno(file), mode)) == NULL) {
	    cerr <<"bzdopen: insufficient memory for compression state\n";
	    free(f);
	    return NULL;
	}
#else
	bzlib_not_compiled();
#endif /* HAVE_BZLIB_H */
	break;
    case IPR_COMPRESS_NONE:	
	f->_fp = file;
	break;
    default:
	cerr << "unknown compression type: " << static_cast<int>(compression) << endl;
	free(f);
	return NULL;
    }
    return f;
}

#ifdef HAVE_BZLIB_H
// XXX why do I have to copy bzip2 typedefs here?  BLAH!
typedef struct {
    FILE*     handle;
    char      buf[BZ_MAX_UNUSED];
    int32_t   bufN;
    bool      writing;
    bz_stream strm;
    int32_t   lastErr;
    bool      initialisedOk;
} bzFile;

typedef void 	BZFILE;
typedef int32_t	Int32;
#define True true

// For some reason bzlib (BZ2_bzflush() doesn't do a thing.  Also we
// want to do it at slightly below 900,000 bytes, which is a default
// buffer size for bzip2.
static
int BZ_API(BZ2_bzflush_my) (BZFILE *b)
{
    Int32   n, n2, ret = BZ_RUN_OK;
    bzFile* bzf = (bzFile*)b;

    while (True) {
	bzf->strm.avail_out = BZ_MAX_UNUSED;
	bzf->strm.next_out = bzf->buf;
	ret = BZ2_bzCompress( &(bzf->strm), BZ_FLUSH );
	if (ret != BZ_RUN_OK && ret != BZ_FLUSH_OK) { 
	    BZ2_bzerror(bzf, &errno);
	    return -1;
	}
	if (bzf->strm.avail_out < BZ_MAX_UNUSED) {
	    n = BZ_MAX_UNUSED - bzf->strm.avail_out;
	    n2 = fwrite ( (void*)(bzf->buf), 1, n, bzf->handle );
	    if (n != n2 || ferror(bzf->handle))
		return -1;
	}
	if (ret == BZ_RUN_OK) break;
    }
    ::fflush ( bzf->handle );
    return 0;
}
#endif /* HAVE_BZLIB_H */


ipr_ret_t	
icmptrain_flush(icmptrain_file_t *file)
{
    int errnum;
    switch (file->_compression) {
    case IPR_COMPRESS_ZLIB:
#ifdef HAVE_ZLIB_H
	{
	    gzFile gz = reinterpret_cast<gzFile>(file->_fp);
	    if (gzflush(gz, Z_SYNC_FLUSH) != Z_OK) {
		const char *err = gzerror(gz, &errnum);
		cerr << "error flushing file: " << err << endl;
		if (errnum == Z_ERRNO)
		    ::perror("ERRNO:");
		return IPR_RET_ZLIB_ERROR;
	    }
	}
#else
	zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;
    case IPR_COMPRESS_BZIP2:
#ifdef HAVE_BZLIB_H
	if (file->_pos < file->_ckpt_pos) {
	    cerr << "Error:   file pos " << file->_pos 
		 << " < checkpoint pos " << file->_ckpt_pos << endl;
	    return IPR_RET_BZLIB_ERROR;
	}
	// let the fun begin
	if (BZ2_bzflush_my(file->_fp) != 0) {
	    ::perror("bzip2 flushing: error writing file");
	    return IPR_RET_BZLIB_ERROR; 
	}
#else
	bzlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;
    case IPR_COMPRESS_NONE:
	if (::fflush((FILE*)file->_fp) != 0)
	    ::perror("fflush:");
	break;
    default:
	cerr << "unknown compression type: " << static_cast<int>(file->_compression) << endl;
	return IPR_RET_BADTYPE;
    }
    file->_ckpt_pos = file->_pos;
    return IPR_RET_OK;
}

ipr_ret_t
icmptrain_close(icmptrain_file_t *file)
{
    switch (file->_compression) {
    case IPR_COMPRESS_ZLIB:
#ifdef HAVE_ZLIB_H
	{
	    gzFile gz = reinterpret_cast<gzFile>(file->_fp);
	    if (gzclose(gz) != Z_OK)
	    return IPR_RET_ZLIB_ERROR;
	}
#else
	zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;
    case IPR_COMPRESS_BZIP2:
#ifdef HAVE_BZLIB_H
	BZ2_bzclose(file->_fp);
#else
	bzlib_not_compiled();
#endif /* HAVE_BZLIB_H */
	break;
    case IPR_COMPRESS_NONE:
	if (fclose(static_cast<FILE*>(file->_fp)) != 0)
	    return IPR_RET_FILE_ERROR;
	break;
    default:
	cerr << "unknown compression type: " << static_cast<int>(file->_compression) << endl;
	return IPR_RET_BADTYPE;
    }
    file->_fp = NULL;
    free(file);
	
    return IPR_RET_OK;
}

uint64_t
icmptrain_tell(icmptrain_file_t *file)
{
    return file->_pos;
}

ipr_ret_t
icmptrain_seek(icmptrain_file_t *file, int64_t offset, int whence)
{
    int err;
    int errnum = 0;
    switch (file->_compression) {
    case IPR_COMPRESS_ZLIB:
#ifdef HAVE_ZLIB_H
	{
	    gzFile gz = reinterpret_cast<gzFile>(file->_fp);
	    err = gzseek(gz, offset, whence);
	    if (err < 0) {
		cerr << "seek error : " << gzerror(gz, &errnum) 
		     << "errno: " << errnum << " to " << offset << endl;
		return IPR_RET_ZLIB_ERROR;
	    }
	}
#else
	zlib_not_compiled();
#endif /* HAVE_ZLIB_H */
	break;
    case IPR_COMPRESS_BZIP2:
	cerr << "seeking is not supported for bzip2 files\n";
	return IPR_RET_FILE_ERROR;
    case IPR_COMPRESS_NONE:
	err = ::fseek((FILE*)file->_fp, offset, whence);
	if (err < 0) {
	    ::perror("seek error : ");
	    return IPR_RET_FILE_ERROR;
	}
	break;
    default:
	cerr << "unknown compression type: " << static_cast<int>(file->_compression) << endl;
	return IPR_RET_BADTYPE;
    }
    if (whence == SEEK_CUR)
	file->_pos += offset;
    else if (whence == SEEK_SET)
	file->_pos = offset;
    else 
	cerr << "Warning: seeking from the end is not fully supported for compressed files\n";

    return IPR_RET_OK;
}

ipr_ret_t
icmptrain_skip(icmptrain_file_t *file, uint64_t off)
{
    while (off > 0) {
	size_t sbytes = LONG_MAX;
	if (sbytes > off)
	    sbytes = off;
	
	ipr_ret_t ret = icmptrain_seek(file, sbytes, SEEK_CUR);
	
	if (ret != IPR_RET_OK)
	    return ret;
	off -= sbytes;
	file->_pos += sbytes;
    }

    return IPR_RET_OK;
}
    
