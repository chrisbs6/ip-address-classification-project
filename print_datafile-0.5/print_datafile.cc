/* -*-  Mode:C++; c-basic-offset:4; tab-width:8; indent-tabs-mode:nil -*- */
/*
 * Copyright (C) 2004-2010 by the University of Southern California
 * $Id: print_datafile.cc 21380 2014-07-03 07:03:21Z johnh $
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

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <getopt.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif /* HAVE_ZLIB_H */

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif /* HAVE_BZLIB_H */

#ifdef HAVE_MAGIC_H
#include <magic.h>
#define MAGIC_GZIP_DSC      "application/x-gzip"
#define MAGIC_BZIP2_DSC     "application/x-bzip2"
#endif /* HAVE_MAGIC_H */

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ostream>
#include <iostream>
#include <iomanip>

#include "icmptrain_datafile.hh"
#include "scramble_crypt.h"

// --- Added definitions ---
#ifndef ulong
typedef unsigned long ulong;
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif
// --- End of added definitions ---

#ifndef lint
static const char rcsid[] =
    "@(#) $Id: print_datafile.cc 21380 2014-07-03 07:03:21Z johnh $";
#endif

using namespace std;

static const char * const NOADDR = "--------";

/* global variables */
int opt_s_short = 0;       /* short output format */
bool print_newline = true; /* so we don't print # for every text record */
bool opt_f_flags = false;  /* print version 2 data record flags */
int opt_t_display_offset = 0;
int64_t offset = 0;

inline void print_data_v1(const icmptrain_probe_record_datav1_t *r, ostream &os, bool verbose) {
    struct in_addr probe = { r->ipr_probe_addr };
    struct in_addr reply = { r->ipr_reply_addr };
    uint type_code = r->ipr_reply_type;

    if (verbose)
        os << int(r->ipr_type) << "/" << int(r->ipr_len) << "\t";

    if (opt_s_short) {
        os << setfill('0') << setw(2) << hex << type_code << dec << "\t"
           << ntohl(r->ipr_time_s) << "\t"
           << ntohl(r->ipr_rtt_us) << "\t"
           << uint(r->ipr_ttl) << "\t";
        if (probe.s_addr == 0)
            os << "-\t";
        else 
            os << setfill('0') << setw(8) << hex << htonl(probe.s_addr) << "\t";
        if (reply.s_addr == 0)
            os << "-\n";
        else 
            os << setfill('0') << setw(8) << hex << htonl(reply.s_addr) << endl;
    } else {
        os << "0x" << setfill('0') << setw(2) << hex << type_code << dec << "\t"
           << ntohl(r->ipr_time_s) << "\t"
           << ntohl(r->ipr_rtt_us) << "\t"
           << uint(r->ipr_ttl) << "\t";
        os << setfill(' ') << setw(16) << ((probe.s_addr == 0) ? NOADDR : inet_ntoa(probe)) << "\t";
        os << setfill(' ') << setw(16) << ((reply.s_addr == 0) ? NOADDR : inet_ntoa(reply)) << endl;
    }
}

void print_data_v2(const icmptrain_probe_record_datav2_t *r, ostream &os, bool verbose) {
    struct in_addr probe = { r->ipr_probe_addr };
    struct in_addr reply = { r->ipr_reply_addr };
    uint type_code = (r->ipr_reply_type << 8) | r->ipr_reply_code;

    if (verbose)
        os << int(r->ipr_type) << "/" << int(r->ipr_len) << "\t";

    if (opt_s_short) {
        os << setfill('0') << setw(4) << hex << type_code << dec << "\t"
           << ntohl(r->ipr_time_s) << "\t"
           << ntohl(r->ipr_rtt_us) << "\t"
           << uint(r->ipr_ttl) << "\t";
        if (probe.s_addr == 0)
            os << "-\t";
        else 
            os << setfill('0') << setw(8) << hex << htonl(probe.s_addr) << "\t";
        if (reply.s_addr == 0)
            os << "-";
        else 
            os << setfill('0') << setw(8) << hex << htonl(reply.s_addr);
        if (opt_f_flags)
            os << "\t" << static_cast<int>(r->ipr_flags) << endl;
        else
            os << endl;
    } else {
        os << "0x" << setfill('0') << setw(4) << hex << type_code << dec << "\t"
           << ntohl(r->ipr_time_s) << "\t"
           << ntohl(r->ipr_rtt_us) << "\t"
           << uint(r->ipr_ttl) << "\t"
           << setfill(' ') << setw(16) << ((probe.s_addr == 0) ? NOADDR : inet_ntoa(probe)) << "\t";
        os << setfill(' ') << setw(16) << ((reply.s_addr == 0) ? NOADDR : inet_ntoa(reply));
        if (opt_f_flags)
            os << "\t" << static_cast<int>(r->ipr_flags) << endl;
        else
            os << endl;
    }
}

void print_data_v3(const icmptrain_probe_record_datav2_t *r3, ostream &os, bool verbose) {
    // For this parser, v3 is printed the same way as v2.
    print_data_v2(r3, os, verbose);
}

void print_txt_v1(const icmptrain_probe_record_txt_v1_t *r, ostream &os, bool verbose) {
    os << "# TXT:\t";
    if (verbose)
        os << int(r->ipr_type) << "/" << int(r->ipr_len) << "\t";
    os << r->ipr_msg << endl;
}

void print_txt_v2(const icmptrain_probe_record_txt_v2_t *r, ostream &os, bool verbose) {
    char cbuf[IPR_MSG_TXT_v2_MAX+1];
    cbuf[IPR_MSG_TXT_v2_MAX] = '\0'; // ensure null termination
    memcpy(cbuf, r->ipr_msg, IPR_MSG_TXT_v2_MAX);
    if (print_newline) {
        if (opt_t_display_offset)
            cout << dec << offset << "\t";
        os << "# TXT:\t";
        if (verbose)
            os << int(r->ipr_type) << "/" << int(r->ipr_len) << "\t";
    }
    os << cbuf; // no newline appended here
    print_newline = (strstr(cbuf, "\n") != nullptr);
}

void print_txt_v3(const icmptrain_probe_record_txt_v3_t *r3, ostream &os, bool verbose) {
    const icmptrain_probe_record_txt_v2_t *r2 = static_cast<const icmptrain_probe_record_txt_v2_t *>(r3);
    print_txt_v2(r2, os, verbose);
}

void usage(const char *progname) {
    cerr << "USAGE:\n\t" << progname << " [-FGghoSsTt";
#ifdef HAVE_ZLIB_H
    cerr << "z";
#endif
#ifdef HAVE_BZLIB_H
    cerr << "j";
#endif
    cerr << "] <input_file>\n\nOptions:\n"
         << "\t-F <t>   : print only records with time >= <t>\n"
         << "\t-G       : output gaps (no responses) to a file\n"
         << "\t-c <n>   : convert records to format <n>\n"
         << "\t-f       : print version 2 flags\n"
         << "\t-g <t>   : define min gap size >= <t>\n"
         << "\t-h       : show this help\n"
         << "\t-k <key> : anonymize IPs using this key file\n"
         << "\t-o <fn>  : output file name (for -G, -c)\n"
         << "\t-p <n>   : while anonymizing, pass through <n> high bits\n"
         << "\t-t       : display byte offset for each record\n"
         << "\t-T <t>   : print only records with time <= <t>\n"
         << "\t-v       : verbose (print record type/length)\n";
#ifdef HAVE_ZLIB_H
    cerr << "\t-z       : assume input is gzip'ed\n";
#endif
#ifdef HAVE_BZLIB_H
    cerr << "\t-j       : assume input is bzip2\n";
#endif
    exit(0);
}

int main(int argc, char *argv[]) {
    char buf[256];
    icmptrain_probe_record_datav1_t *rec1     = (icmptrain_probe_record_datav1_t *)buf;
    icmptrain_probe_record_datav2_t *rec2     = (icmptrain_probe_record_datav2_t *)buf;
    icmptrain_probe_record_datav3_t *rec3     = (icmptrain_probe_record_datav3_t *)buf;
    icmptrain_probe_record_txt_v1_t *rec_txt1 = (icmptrain_probe_record_txt_v1_t *)buf;
    icmptrain_probe_record_txt_v2_t *rec_txt2 = (icmptrain_probe_record_txt_v2_t *)buf;

    int use_zlib = 0;
    int use_bzip2 = 0;
    int opt;
    icmptrain_file_t *input_file = NULL;
    const char *progname = argv[0];
    uint32_t opt_F_tsfrom = 0;
    uint32_t opt_T_tsto = ~(uint32_t)0;
    uint64_t opt_S_skip = 0;

    icmptrain_file_t *out_file = NULL;
    const char *opt_o_outfile = NULL;
    int opt_c_conv = 0;
    int opt_G_outgaps = 0;
    ulong opt_g_gaps = 0;
    const char *opt_k_key = NULL;
    int opt_p_pass = 0;
    int opt_r_reverse = 0;
    int opt_v_verbose = 0;
    uint32_t prev_ts = 0;
    ulong prev_offset = 0;
    icmptrain_probe_record_datav1_t prev_rec1 = {0,};
    icmptrain_probe_record_datav2_t prev_rec2 = {0,};

    while ((opt = getopt(argc, argv, "F:Gc:fg:hjk:o:p:rS:sT:tvz")) != -1) {
        switch(opt) {
            case 'F': opt_F_tsfrom = atol(optarg); break;
            case 'G': ++opt_G_outgaps; break;
            case 'S': opt_S_skip = atoll(optarg); break;
            case 'T': opt_T_tsto = atol(optarg); break;
            case 'c': opt_c_conv = atoi(optarg); break;
            case 'f': opt_f_flags = true; break;
            case 'g': opt_g_gaps = (ulong)atol(optarg); break;
            case 'h': usage(progname); break;
            case 'j': use_bzip2 = 1; break;
            case 'k': opt_k_key = optarg; break;
            case 'o': opt_o_outfile = optarg; break;
            case 'p': opt_p_pass = atoi(optarg); break;
            case 'r': opt_r_reverse = 1; break;
            case 's': opt_s_short = 1; break;
            case 't': opt_t_display_offset = 1; break;
            case 'v': opt_v_verbose = 1; break;
            case 'z': use_zlib = 1; break;
            default: usage(progname);
        }
    }
    argc -= optind;
    argv += optind;
    if (opt_p_pass != 0 && opt_k_key == NULL)
        cerr << "Warning: -p without -k has no effect\n";
    if (opt_r_reverse != 0 && opt_k_key == NULL)
        cerr << "Warning: -r without -k has no effect\n";
    if (use_bzip2 && use_zlib) {
        cerr << "Error: options -j and -z are mutually exclusive\n";
        exit(1);
    }

    if (argc > 1)
        usage(progname);
    if (argc == 1) {
        const char *path = argv[0];
        stdin = freopen(path, "r", stdin);
        if (stdin == NULL) {
            cerr << "cannot open file " << strerror(errno) << endl;
            exit(1);
        }
#ifdef HAVE_MAGIC_H
        if (!use_zlib && !use_bzip2) {
            magic_t cookie = magic_open(MAGIC_MIME);
            const char *dsc;
            if (cookie != NULL) {
                magic_load(cookie, NULL);
                if ((dsc = magic_file(cookie, path)) != 0) {
                    use_zlib = (strncmp(MAGIC_GZIP_DSC, dsc, strlen(MAGIC_GZIP_DSC)) == 0);
                    use_bzip2 = (strncmp(MAGIC_BZIP2_DSC, dsc, strlen(MAGIC_BZIP2_DSC)) == 0);
                }
                magic_close(cookie);
            }
        }
#endif
    }
    ipr_compress_t compression = IPR_COMPRESS_NONE;
    if (use_zlib)
        compression = IPR_COMPRESS_ZLIB;
    else if (use_bzip2)
        compression = IPR_COMPRESS_BZIP2;
    else
        compression = IPR_COMPRESS_NONE;

    input_file = icmptrain_remap(stdin, "rb", compression);
    if (input_file == NULL) {
        cerr << "cannot remap stdin\n";
        exit(1);
    }
    if (opt_o_outfile) {
        FILE *f = fopen(opt_o_outfile, "w");
        if (f == NULL) {
            cerr << "Error opening " << opt_o_outfile << ": " << strerror(errno);
            exit(1);
        } else {
            out_file = icmptrain_remap(f, "wb", compression);
        }
    }
    if (opt_c_conv) {
        if (out_file == 0)
            out_file = icmptrain_remap(stdout, "wb", compression);
        int ret = 0;
        char vers[1024] = "Converted to: ";
        strcat(vers, icmptrain_datafile_hdr_vers());
        switch(opt_c_conv) {
            case 3: ret = icmptrain_write_txt_v3(out_file, vers, strlen(vers) + 1); break;
            case 2: ret = icmptrain_write_txt_v2(out_file, vers, strlen(vers) + 1); break;
            case 1: ret = icmptrain_write_txt_v1(out_file, vers, strlen(vers) + 1); break;
            default:
                cerr << "Unknown output conversion version: " << opt_c_conv << endl;
                exit(1);
        }
        if (ret) {
            perror("cannot write output");
            exit(1);
        }
    } else {
        cout << "#fsdb -F t ";
        if (opt_t_display_offset)
            cout << "off\t";
        if (opt_v_verbose)
            cout << "typelen\t";
        if (opt_s_short)
            cout << "Sreply_type\ttime_s\trtt_us\tttl\tSprobe_addr\tSreply_addr";
        else
            cout << "reply_type\ttime_s\trtt_us\tttl\tprobe_addr\treply_addr";
        if (opt_f_flags)
            cout << "\tflags\n";
        else
            cout << endl;
    }
    if (opt_S_skip > 0) {
        if (icmptrain_skip(input_file, opt_S_skip) < 0) {
            cerr << "cannot skip to " << opt_S_skip << " in input file (eof?)\n";
            exit(1);
        }
    }

    if (opt_k_key) {
        FILE *keyfile;
        if ((keyfile = fopen(opt_k_key, "r")) == NULL) {
            if (errno == ENOENT)
                cerr << "Warning: keyfile " << opt_k_key << " does not exist and will be created\n";
            else {
                cerr << "Error: keyfile " << opt_k_key << " cannot be read: " << strerror(errno) << endl;
                exit(1);
            }
        } else {
            fclose(keyfile);
        }
        if (scramble_init_from_file(opt_k_key, SCRAMBLE_BLOWFISH, SCRAMBLE_BLOWFISH, NULL) < 0) {
            cerr << "error reading keyfile " << opt_k_key << endl;
            exit(1);
        }
    }
    
    for (;;) {
        int err;
        if ((err = icmptrain_read(input_file, buf, sizeof(buf))) < 0) {
            if (err == IPR_RET_EOF)
                break;
            if (errno != 0)
                perror("error reading datafile");
            else
                cerr << "error reading datafile: " << err << endl;
            exit(1);
        }

        switch(rec1->ipr_type) {
            case IPR_TYPE_DATAv1: {
                if (opt_k_key) {
                    if (rec1->ipr_probe_addr)
                        rec1->ipr_probe_addr = (opt_r_reverse) ? unscramble_ip4(rec1->ipr_probe_addr, opt_p_pass)
                                                               : scramble_ip4(rec1->ipr_probe_addr, opt_p_pass);
                    if (rec1->ipr_reply_addr)
                        rec1->ipr_reply_addr = (opt_r_reverse) ? unscramble_ip4(rec1->ipr_reply_addr, opt_p_pass)
                                                               : scramble_ip4(rec1->ipr_reply_addr, opt_p_pass);
                }
                if (opt_c_conv == 3) {
                    icmptrain_probe_record_datav2_t r3;
                    r3.ipr_reply_type = (rec1->ipr_reply_type >> 4);
                    r3.ipr_reply_code = (rec1->ipr_reply_type & 0x0f);
                    r3.ipr_ttl = rec1->ipr_ttl;
                    r3.ipr_time_s = rec1->ipr_time_s;
                    r3.ipr_rtt_us = rec1->ipr_rtt_us;
                    r3.ipr_probe_addr = rec1->ipr_probe_addr;
                    r3.ipr_reply_addr = rec1->ipr_reply_addr;
                    r3.ipr_zero16 = 0;
                    r3.ipr_flags = 0;
                    icmptrain_write_data_v3(out_file, &r3);
                    break;
                } else if (opt_c_conv == 2) {
                    icmptrain_probe_record_datav2_t r2;
                    r2.ipr_reply_type = (rec1->ipr_reply_type >> 4);
                    r2.ipr_reply_code = (rec1->ipr_reply_type & 0x0f);
                    r2.ipr_ttl = rec1->ipr_ttl;
                    r2.ipr_time_s = rec1->ipr_time_s;
                    r2.ipr_rtt_us = rec1->ipr_rtt_us;
                    r2.ipr_probe_addr = rec1->ipr_probe_addr;
                    r2.ipr_reply_addr = rec1->ipr_reply_addr;
                    r2.ipr_zero16 = 0;
                    r2.ipr_flags = 0;
                    icmptrain_write_data_v2(out_file, &r2);
                    break;
                } else if (opt_c_conv == 1) {
                    icmptrain_write_data_v1(out_file, rec1);
                    break;
                }
                uint32_t ts = ntohl(rec1->ipr_time_s);
                if (opt_g_gaps) {
                    if (rec1->ipr_reply_type == IPR_REPLY_MKREPLY(ICMP_ECHOREPLY, 0)) {
                        ulong diff;
                        diff = (ts > prev_ts) ? ts - prev_ts : prev_ts - ts;
                        if (prev_ts && diff >= opt_g_gaps) {
                            cout << "diff = " << diff << ":\n";
                            if (opt_t_display_offset)
                                cout << offset - prev_offset << "\t";
                            print_data_v1(&prev_rec1, cout, opt_v_verbose);
                            if (opt_t_display_offset)
                                cout << dec << offset << "\t";
                            print_data_v1(rec1, cout, opt_v_verbose);
                            if (out_file && opt_G_outgaps) {
                                long size = prev_offset;
                                char copybuf[1024];
                                if (icmptrain_seek(input_file, -size, SEEK_CUR) < 0) {
                                    cerr << "cannot reposition input file for gap filtering\n";
                                    exit(1);
                                }
                                size -= rec1->ipr_len;
                                while (size > 0) {
                                    icmptrain_probe_record_datav1_t *r1 = (icmptrain_probe_record_datav1_t *)copybuf;
                                    icmptrain_probe_record_txt_v1_t *rt = (icmptrain_probe_record_txt_v1_t *)copybuf;
                                    if (icmptrain_read(input_file, copybuf, sizeof(copybuf)) < 0) {
                                        cerr << "error reading from file...\n";
                                        exit(1);
                                    }
                                    if (r1->ipr_type == IPR_TYPE_DATAv1)
                                        err = icmptrain_write_data_v1(out_file, r1);
                                    else if (r1->ipr_type == IPR_TYPE_TXT_v1)
                                        err = icmptrain_write_txt_v1(out_file, rt->ipr_msg, IPR_MSG_TXT_v1_MAX);
                                    else
                                        abort();
                                    if (err < 0)
                                        cerr << "error writing to file\n";
                                    size -= r1->ipr_len;
                                }
                                icmptrain_flush(out_file);
                            }
                        }
                        prev_ts = ts;
                        prev_rec1 = *rec1;
                        prev_offset = rec1->ipr_len;
                    } else {
                        prev_offset += rec1->ipr_len;
                    }
                    break;
                }
                if (ts >= opt_F_tsfrom && ts <= opt_T_tsto) {
                    if (opt_t_display_offset)
                        cout << dec << offset << "\t";
                    print_data_v1(rec1, cout, opt_v_verbose);
                }
                break;
            }
            case IPR_TYPE_DATAv2:
            case IPR_TYPE_DATAv3: {
                if (opt_k_key) {
                    if (rec2->ipr_probe_addr)
                        rec2->ipr_probe_addr = (opt_r_reverse) ? unscramble_ip4(rec2->ipr_probe_addr, opt_p_pass)
                                                               : scramble_ip4(rec2->ipr_probe_addr, opt_p_pass);
                    if (rec2->ipr_reply_addr)
                        rec2->ipr_reply_addr = (opt_r_reverse) ? unscramble_ip4(rec2->ipr_reply_addr, opt_p_pass)
                                                               : scramble_ip4(rec2->ipr_reply_addr, opt_p_pass);
                }
                if (opt_c_conv == 3) {
                    if (rec3->ipr_reply_type == ICMP_TIME_EXCEEDED &&
                        ((rec3->ipr_flags & IPR_FLAG_DUMPED) == 0)) {
                        rec3->ipr_rtt_us = 0;
                    }
                    icmptrain_write_data_v3(out_file, rec3);
                    break;
                } else if (opt_c_conv == 2) {
                    icmptrain_write_data_v2(out_file, rec2);
                    break;
                } else if (opt_c_conv == 1) {
                    icmptrain_probe_record_datav1_t r1;
                    r1.ipr_reply_type = IPR_REPLY_MKREPLY(rec2->ipr_reply_type, rec2->ipr_reply_code);
                    r1.ipr_ttl = rec2->ipr_ttl;
                    r1.ipr_time_s = rec2->ipr_time_s;
                    r1.ipr_rtt_us = rec2->ipr_rtt_us;
                    r1.ipr_probe_addr = rec2->ipr_probe_addr;
                    r1.ipr_reply_addr = rec2->ipr_reply_addr;
                    icmptrain_write_data_v1(out_file, &r1);
                    break;
                }
                uint32_t ts = ntohl(rec2->ipr_time_s);
                if (opt_g_gaps) {
                    if (rec2->ipr_reply_type == ICMP_ECHOREPLY && rec2->ipr_reply_code == 0) {
                        ulong diff;
                        diff = (ts > prev_ts) ? ts - prev_ts : prev_ts - ts;
                        if (prev_ts && diff >= opt_g_gaps) {
                            cout << "diff = " << diff << ":\n";
                            if (opt_t_display_offset)
                                cout << offset - prev_offset << "\t";
                            print_data_v2(&prev_rec2, cout, opt_v_verbose);
                            if (opt_t_display_offset)
                                cout << dec << offset << "\t";
                            print_data_v2(rec2, cout, opt_v_verbose);
                            if (out_file && opt_G_outgaps) {
                                long size = prev_offset;
                                char copybuf[1024];
                                if (icmptrain_seek(input_file, -size, SEEK_CUR) < 0) {
                                    cerr << "cannot reposition input file for gap filtering\n";
                                    exit(1);
                                }
                                size -= rec2->ipr_len;
                                while (size > 0) {
                                    icmptrain_probe_record_datav2_t *r2 = (icmptrain_probe_record_datav2_t *)copybuf;
                                    icmptrain_probe_record_txt_v2_t *rt = (icmptrain_probe_record_txt_v2_t *)copybuf;
                                    if (icmptrain_read(input_file, copybuf, sizeof(copybuf)) < 0) {
                                        cerr << "error reading from file...\n";
                                        exit(1);
                                    }
                                    if (r2->ipr_type == IPR_TYPE_DATAv2)
                                        err = icmptrain_write_data_v2(out_file, r2);
                                    else if (r2->ipr_type == IPR_TYPE_TXT_v2)
                                        err = icmptrain_write_txt_v2(out_file, rt->ipr_msg, IPR_MSG_TXT_v2_MAX);
                                    else
                                        abort();
                                    if (err < 0)
                                        cerr << "error writing to file\n";
                                    size -= r2->ipr_len;
                                }
                                icmptrain_flush(out_file);
                            }
                        }
                        prev_ts = ts;
                        prev_rec2 = *rec2;
                        prev_offset = rec2->ipr_len;
                    } else {
                        prev_offset += rec2->ipr_len;
                    }
                    break;
                }
                if (ts >= opt_F_tsfrom && ts <= opt_T_tsto) {
                    if (opt_t_display_offset)
                        cout << dec << offset << "\t";
                    print_data_v2(rec2, cout, opt_v_verbose);
                }
                break;
            }
            case IPR_TYPE_TXT_v1:
                if (opt_c_conv == 2) {
                    strcat(rec_txt1->ipr_msg, "\n");
                    icmptrain_write_txt_v2(out_file, rec_txt1->ipr_msg, strlen(rec_txt1->ipr_msg) + 1);
                    break;
                } else if (opt_c_conv == 1) {
                    icmptrain_write_txt_v1(out_file, rec_txt1->ipr_msg, strlen(rec_txt1->ipr_msg) + 1);
                    break;
                }
                print_txt_v1(rec_txt1, cout, opt_v_verbose);
                break;
            case IPR_TYPE_TXT_v2:
            case IPR_TYPE_TXT_v3:
                if (opt_c_conv == 1) {
                    strncpy(rec_txt1->ipr_msg, rec_txt2->ipr_msg, IPR_MSG_TXT_v2_MAX);
                    rec_txt1->ipr_msg[IPR_MSG_TXT_v2_MAX] = '\0';
                    icmptrain_write_txt_v1(out_file, rec_txt1->ipr_msg, strlen(rec_txt1->ipr_msg) + 1);
                    break;
                } else if (opt_c_conv == 2) {
                    icmptrain_write_txt_v2(out_file, rec_txt2->ipr_msg, IPR_MSG_TXT_v2_MAX);
                    break;
                } else if (opt_c_conv == 3) {
                    icmptrain_write_txt_v3(out_file, rec_txt2->ipr_msg, IPR_MSG_TXT_v2_MAX);
                    break;
                }
                print_txt_v2(rec_txt2, cout, opt_v_verbose);
                break;
            default:
                cerr << "unknown record type: 0x" << hex << static_cast<int>(rec1->ipr_type) << endl;
                exit(1);
        }
        offset += rec1->ipr_len;
    }
    icmptrain_close(input_file);
    if (out_file)
        icmptrain_close(out_file);
    return 0;
}
