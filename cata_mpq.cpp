#include "stdafx.h"
#include <celsus/MemoryMappedFile.hpp>
#include <cassert>
#include <celsus/celsus.hpp>
#include <boost/scoped_array.hpp>
#include <limits>
#include <set>
#include <bzlib.h>
#include <zlib.h>
#include <direct.h>
#include "md5.h"
#include "pklib.h"

using namespace std;
using namespace boost;

// make some less annoying types
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

// infos from http://wiki.devklog.net/index.php?title=The_MoPaQ_Archive_Format

extern "C" {
	void hashlittle2( const void *key, size_t length, uint32_t *pc, uint32_t *pb);
};

class FileReader
{
public:
	FileReader();
	~FileReader();
	bool open(const char *filename);
	void seek(uint64_t ofs, int org) const;
	bool read(void *buf, uint32_t len, uint32_t *bytes_read) const;
	bool read_ofs(void *buf, uint64_t ofs, uint32_t len, uint32_t *bytes_read) const;
	uint64_t filesize() const { return _file_size; }
private:
	HANDLE _file;
	uint64_t _file_size;
};


#pragma pack(push, 1)
struct MpqHeader
{
	char     magic[4];
	uint32_t header_size;
	uint32_t archive_size;
	int16_t  format_version;
	int16_t  sector_size_shift;
	uint32_t hash_table_offset;
	uint32_t block_table_offset;
	int32_t  hash_table_entries;
	int32_t  block_table_entries;

	// v2
	int64_t  extended_block_table_entries;
	uint16_t hash_table_offset_high;
	uint16_t block_table_offset_high;

	// v3
	uint64_t archive_size64;
	uint64_t bet_table_offset64;
	uint64_t het_table_offset64;

	// v4
	uint64_t hash_table_size64;
	uint64_t block_table_size64;
	uint64_t hi_block_table_size64;
	uint64_t het_table_size64;
	uint64_t bet_table_size64;

	uint32_t raw_chunk_size;

#define MD5_DIGEST_SIZE 0x10
	uint8_t md5_block_table[MD5_DIGEST_SIZE];
	uint8_t md5_hash_table[MD5_DIGEST_SIZE];
	uint8_t md5_hi_block_table[MD5_DIGEST_SIZE];
	uint8_t md5_bet_table[MD5_DIGEST_SIZE];
	uint8_t md5_het_table[MD5_DIGEST_SIZE];
	uint8_t md5_mpq_header[MD5_DIGEST_SIZE];
};

struct BlockTableEntry {
	int32_t ofs;
	int32_t len;
	int32_t file_size;
	int32_t flags;
};
/*
enum BlockTableFlags {
	kBtFlagsImploded       = 0x00000100,
	kBtFlagsCompressed     = 0x00000200,
	kBtFlagsEncrypted      = 0x00010000,
	kBtFlagsAdjustedKey    = 0x00020000,
	kBtFlagsChecksum       = 0x04000000,
	kBtFlagsSingleUnit     = 0x10000000,
	kBtFlagsDeletionmarker = 0x20000000,
	kBtFlagsFile           = 0x80000000,
};
*/
#define MPQ_FILE_IMPLODE         0x00000100 // Implode method (By PKWARE Data Compression Library)
#define MPQ_FILE_COMPRESS        0x00000200 // Compress methods (By multiple methods)
#define MPQ_FILE_COMPRESSED      0x0000FF00 // File is compressed
#define MPQ_FILE_ENCRYPTED       0x00010000 // Indicates whether file is encrypted 
#define MPQ_FILE_FIX_KEY         0x00020000 // File decryption key has to be fixed
#define MPQ_FILE_PATCH_FILE      0x00100000 // The file is a patch file. Raw file data begin with TPatchInfo structure
#define MPQ_FILE_SINGLE_UNIT     0x01000000 // File is stored as a single unit, rather than split into sectors (Thx, Quantam)
#define MPQ_FILE_DELETE_MARKER   0x02000000 // File is a deletion marker, indicating that the file no longer exists.
// The file is only 1 byte long and its name is a hash
#define MPQ_FILE_SECTOR_CRC      0x04000000 // File has checksums for each sector.
// Ignored if file is not compressed or imploded.
#define MPQ_FILE_EXISTS          0x80000000 // Set if file exists, reset when the file was deleted
#define MPQ_FILE_REPLACEEXISTING 0x80000000 // Replace when the file exist (SFileAddFile)


// Compression types for multiple compressions
#define MPQ_COMPRESSION_HUFFMANN       0x01 // Huffmann compression (used on WAVE files only)
#define MPQ_COMPRESSION_ZLIB           0x02 // ZLIB compression
#define MPQ_COMPRESSION_PKWARE         0x08 // PKWARE DCL compression
#define MPQ_COMPRESSION_BZIP2          0x10 // BZIP2 compression (added in Warcraft III)
#define MPQ_COMPRESSION_SPARSE         0x20 // Sparse compression (added in Starcraft 2)
#define MPQ_COMPRESSION_ADPCM_MONO     0x40 // IMA ADPCM compression (mono)
#define MPQ_COMPRESSION_ADPCM_STEREO   0x80 // IMA ADPCM compression (stereo)

struct HashTableEntry {
	uint32_t hash_a;  // file path hash, using method a
	uint32_t hash_b;  // file path hash, using method b
	int16_t language;
	int8_t platform;
	int8_t padding;
	int32_t block_table_index;
};


#define HET_TABLE_SIGNATURE 0x1A544548      // 'HET\x1a'
#define BET_TABLE_SIGNATURE 0x1A544542      // 'BET\x1a'

//-----------------------------------------------------------------------------
// Local structures

// Header for HET and BET tables
#pragma pack(push, 1)
struct ExtTableHeader {
	uint32_t dwSignature;                      // 'HET\x1A' or 'BET\x1A'
	uint32_t dwVersion;                        // Version. Seems to be always 1
	uint32_t dwDataSize;                       // Size of the contained table

	// Followed by the table header
	// Followed by the table data
};

struct HetTable : public ExtTableHeader {
	uint32_t dwTableSize;                      // Size of the entire hash table, including the header (in bytes)
	uint32_t dwFileCount;                      // Number of used file entries in the HET table
	uint32_t dwHashTableSize;                  // Size of the hash table, (in bytes)
	uint32_t dwHashEntrySize;                  // Effective size of the hash entry (in bits)
	uint32_t dwTotalIndexSize;                 // Total of index entry, in bits
	uint32_t dwUnknown14;
	uint32_t dwIndexSize;                      // Effective size of the index entry
	uint32_t dwBlockTableSize;                 // Size of the block index subtable (in bytes)
};

struct BetTable : public ExtTableHeader {
	uint32_t dwTableSize;                      // Size of the entire hash table, including the header (in bytes)
	uint32_t dwFileCount;                      // Number of files in the ext block table
	uint32_t dwUnknown08;
	uint32_t dwTableEntrySize;                 // Size of one table entry (in bits)
	uint32_t dwBitIndex_FilePos;               // Bit index of the file position (within the entry record)
	uint32_t dwBitIndex_FileSize;              // Bit index of the file size (within the entry record)
	uint32_t dwBitIndex_CompressedSize;        // Bit index of the compressed size (within the entry record)
	uint32_t dwBitIndex_FlagIndex;             // Bit index of the flag index (within the entry record)
	uint32_t dwBitIndex_Unknown;               // Bit index of the ??? (within the entry record)
	uint32_t dwFilePosBits;                    // Bit size of file position (in the entry record)
	uint32_t dwFileSizeBits;                   // Bit size of file size (in the entry record)
	uint32_t dwCompressedSizeBits;             // Bit size of compressed file size (in the entry record)
	uint32_t dwFlagsBits;                      // Bit size of flags index (in the entry record)
	uint32_t dwUnknownBits;                    // Bit size of ??? (in the entry record)
	uint32_t dwTotalBetHashSize;               // Total size of the BET hash
	uint32_t dwBetHashSizeExtra;               // Extra bits in the BET hash
	uint32_t dwBetHashSize;                    // Effective size of BET hash (in bits)
	uint32_t dwBetHashArraySize;               // Size of BET hashes array, in bytes
	uint32_t dwFlagCount;                      // Number of flags in the following array
};
#pragma pack(pop)


typedef struct _MPQ_FILE_BLOCK_ENTRY
{
	uint32_t dwFilePosLo;
	uint32_t dwFilePosHi;
	uint32_t dwCmpSizeLo;
	uint32_t dwCmpSizeHi;
	uint32_t dwFileSizeLo;
	uint32_t dwFileSizeHi;
	uint32_t dwFlags;
	uint32_t result64_lo;
	uint32_t result64_hi;
	uint32_t result32;
	uint32_t result128_1;
	uint32_t result128_2;
	uint32_t result128_3;
	uint32_t result128_4;
	USHORT field_38;

} MPQ_FILE_BLOCK_ENTRY, *PMPQ_FILE_BLOCK_ENTRY;

// Structure for bit array
typedef struct _BIT_ARRAY
{
	void LoadBits(unsigned int nBitPosition,
		unsigned int nBitLength,
		void * pvBuffer,
		int nResultSize);

	uint32_t NumberOfBits;                     // Total number of bits that are available
	BYTE Elements[1];                       // Array of elements (variable length)

} BIT_ARRAY, *PBIT_ARRAY;


struct ExtendedTableHeader
{
	uint32_t signature;
	uint32_t version;
	uint32_t data_size;
};


// Structure for parsed HET table
struct TMPQHetTable
{
	uint32_t      dwTotalIndexSize;            // Size of one index entry (in bits)
	uint32_t      field_4;
	uint32_t      dwIndexSize;                 // Effective size of the index entry
	LPBYTE     pHashPart1;                  // Array of HashPart1 values (see GetFileIndex_HetBet() for more info)
	PBIT_ARRAY pBlockIndexes;
	uint32_t      dwTableSize;
	uint32_t      dwFileCount;
	uint32_t      dwHashBitSize;               // Effective number of bits in the hash
	ULONGLONG  AndMask64;
	ULONGLONG  OrMask64;
};

// Structure for parsed BET table
struct TMPQBetTable
{
	PBIT_ARRAY pHashPart2;                  // Bit array of NameHashPart2 values (see GetFileIndex_HetBet() for more info)
	PBIT_ARRAY pBlockTable;                 // Bit-based block table
	LPDWORD pFileFlags;                     // Array of file flags

	uint32_t dwTableEntrySize;                 // Size of one table entry, in bits
	uint32_t dwBitIndex_FilePos;               // Bit index of the file position in the table entry
	uint32_t dwBitIndex_FSize;                 // Bit index of the file size in the table entry
	uint32_t dwBitIndex_CSize;                 // Bit index of the compressed size in the table entry
	uint32_t dwBitIndex_FlagIndex;             // Bit index of the flag index in the table entry
	uint32_t dwBitIndex_Unknown;               // Bit index of ??? in the table entry
	uint32_t dwFilePosBits;                    // Size of file offset (in bits) within table entry
	uint32_t dwFileSizeBits;                   // Size of file size (in bits) within table entry
	uint32_t dwCmpSizeBits;                    // Size of compressed file size (in bits) within table entry
	uint32_t dwFlagsBits;                      // Size of flag index (in bits) within table entry
	uint32_t dwUnknownBits;                    // Size of ??? (in bits) within table entry
	uint32_t TotalNameHash2Size;               // Total size of NameHashPart2
	uint32_t field_48;
	uint32_t NameHash2Size;                    // Effective size of the NameHashPart2
	uint32_t dwFileCount;                      // Number of used entries in the table
	uint32_t dwFlagCount;                      // Number of entries in pFileFlags

	//  vector<INT64>  field_5C;
	//  vector<uint32_t>  field_74;
	//  vector<INT128> field_8C;
	//  vector<BYTE>   field_A4;
	uint32_t dwOpenFlags;

};


#pragma pack(pop)

#define BLOCK_OFFSET_ADJUSTED_KEY 0x00020000L

bool find_header(const FileReader &f, MpqHeader *header)
{
	uint32_t magic = 'M' << 24 | 'P' << 16 | 'Q' << 8 | 0x1a;

	const int cBufferSize = 4096;
	byte buf[cBufferSize + sizeof(MpqHeader)];
	uint32_t bytes_read;

	while (f.read(buf, sizeof(buf), &bytes_read)) {

		const int cSectorSize = 512;
		for (int i = 0; i < cBufferSize / cSectorSize; ++i) {
			// the header must begin at a disk sector boundary
			MpqHeader *h = (MpqHeader *)&buf[i*cSectorSize];
			if (h->magic[0] == 'M' && h->magic[1] == 'P' && h->magic[2] == 'Q' && h->magic[3] == 0x1a) {
				memcpy(header, h, sizeof(MpqHeader));
				return true;
			}
		}

		f.seek(sizeof(MpqHeader), SEEK_CUR);
	}

	return false;
}

FileReader::FileReader()
	: _file(INVALID_HANDLE_VALUE)
	, _file_size(~0)
{
}

FileReader::~FileReader()
{
	if (_file != INVALID_HANDLE_VALUE)
		CloseHandle(_file);
}

void FileReader::seek(uint64_t ofs, int org) const
{
	DWORD method[] = { FILE_BEGIN, FILE_CURRENT, FILE_END};
	LONG upper = (LONG)(ofs >> 32);
	SetFilePointer(_file, (DWORD)(ofs & 0xffffffff), upper ? &upper : NULL, method[org]);
}

bool FileReader::read(void *buf, uint32_t len, uint32_t *bytes_read) const
{
	DWORD tmp;
	if (!ReadFile(_file, buf, len, bytes_read ? (DWORD *)bytes_read : &tmp, NULL))
		return false;
	return true;
}

bool FileReader::read_ofs(void *buf, uint64_t ofs, uint32_t len, uint32_t *bytes_read) const
{
	seek(ofs, FILE_BEGIN);
	return read(buf, len, bytes_read);
}

bool FileReader::open(const char *filename)
{
	_file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_file == INVALID_HANDLE_VALUE)
		return false;

	DWORD lo, hi;
	lo = GetFileSize(_file, &hi);
	_file_size = (uint64_t)hi << 32 | lo;
	return true;
}

bool verify_md5(const byte *data, int len, const byte *digest)
{
	md5_state_s md5;
	md5_init(&md5);
	md5_append(&md5, data, len);
	byte d[MD5_DIGEST_SIZE];
	md5_finish(&md5, d);
	return memcmp(d, digest, MD5_DIGEST_SIZE) == 0;
}

template <typename T>
T fill_bits(int n)
{
	if (n == sizeof(T) * 8)
		return ~0;
	// return a mask that fill up to bit n
	return ((T)1 << n) - 1;
}

template <typename T>
T packed_bits(const void *base, uint64_t ofs, uint32_t len)
{
	uint32_t t_size = 8 * sizeof(T);
	uint32_t start_ofs = ofs % 8;
	const T *snapped = (const T *)((const uint8_t *)base + ofs / 8);
	T start_mask = ~fill_bits<T>(start_ofs);
	T end_mask = fill_bits<T>((start_ofs + len)% t_size);

	// does the block stradle 2 memory locations?
	if (start_ofs + len <= t_size) {
		return (*snapped & (start_mask & end_mask)) >> start_ofs;
	}

	return (snapped[0] & start_mask) >> start_ofs | (snapped[1] & end_mask) << (t_size - start_ofs);
}

template <typename T>
bool bit_compare(const T *base, int ofs, T key, uint32_t len)
{
	// look for key of length len bits, starting at base + ofs (ofs is in bits)
	const T TSize = 8 * sizeof(T);

	T ofs_mod = ofs % TSize;
	// do we need to compare across boundaries?
	if (TSize - ofs_mod >= len) {
		// no
		T key_mask = fill_bits<T>(len);
		T tmp = base[ofs / TSize];
		T tmp2 = base[ofs / TSize] >> ofs_mod;
		return ((base[ofs / TSize] >> ofs_mod) & key_mask) == (key & key_mask);
	} 

	// calc upper and lower mask
	T l = TSize - ofs_mod;  // # bits used in lower compare
	T h = len - l;          // # bits used in upper compare
	T lower_key_mask = fill_bits<T>(l);
	T upper_key_mask = fill_bits<T>(h);
	return 
		(((base[ofs / TSize + 0] >> ofs_mod) & lower_key_mask) == (key & lower_key_mask)) &&
		 ((base[ofs / TSize + 1] & upper_key_mask) == ((key >> l) & upper_key_mask));
}

void verify_file_table(const BetTable *bet_header, const uint8_t *bet_file_table)
{
	for (DWORD i = 0; i < bet_header->dwFileCount; ++i) {
		uint64_t file_pos = packed_bits<uint64_t>(bet_file_table, i * bet_header->dwTableEntrySize + bet_header->dwBitIndex_FilePos, bet_header->dwFilePosBits);
		uint64_t file_size = packed_bits<uint64_t>(bet_file_table, i * bet_header->dwTableEntrySize + bet_header->dwBitIndex_FileSize, bet_header->dwFileSizeBits);
		uint64_t file_csize = packed_bits<uint64_t>(bet_file_table, i * bet_header->dwTableEntrySize + bet_header->dwBitIndex_CompressedSize, bet_header->dwCompressedSizeBits);
		uint64_t file_flags = packed_bits<uint64_t>(bet_file_table, i * bet_header->dwTableEntrySize + bet_header->dwBitIndex_FlagIndex, bet_header->dwFlagsBits);
		uint64_t file_unknown = packed_bits<uint64_t>(bet_file_table, i * bet_header->dwTableEntrySize + bet_header->dwBitIndex_Unknown, bet_header->dwUnknownBits);
		int a = 10;
	}
}

void verify_file_idx(const HetTable *het_header, uint8_t *file_indices)
{
	set<uint32_t> files;
	for (size_t i = 0; i < het_header->dwHashTableSize; ++i) {
		uint32_t file_idx = packed_bits<uint32_t>(file_indices, i * het_header->dwTotalIndexSize, het_header->dwIndexSize);
		files.insert(file_idx);
		int aa = 0;
	}
}


struct MpqLoader {
	MpqLoader();
	bool load(const char *filename);
	bool load_file(const char *filename, uint8 **data, uint64 *len);
	bool extract(const char *filename);

	int32_t find_file(const char *filename);
	bool load_file_data(int32 idx, uint32 *file_pos, uint32 *file_size, uint32 *compressed_size, uint32 *flags, uint32 *unknown);

//private:
	// Different types of hashes to make with hash_string
	enum HashType {
		HashTypeTableOffset = 0,
		HashTypeMethodA = 1,
		HashTypeMethodB = 2,
		HashTypeBlockTable = 3,
	};

	void init_crypt_table();
	void decrypt_data(void *lpbyBuffer, uint32_t dwLength, uint32_t dwKey);
	uint32_t hash_string(const char *lpszString, uint32_t dwHashType);

	FileReader f;

	MpqHeader _header;
	HetTable *_het_header;
	BetTable *_bet_header;
	uint8 *_file_indices;
	uint8 *_bet_hashes;
	uint8 *_het_hashes;
	uint8 *_bet_file_table;
	uint32 *_bet_file_flags;
	scoped_array<byte> _het_data;
	scoped_array<byte> _bet_data;
	scoped_array<BlockTableEntry> _block_table;
	scoped_array<HashTableEntry> _hash_table;

	uint32 _crypt_table[0x500];
	//uint8;
};

MpqLoader::MpqLoader()
	: _het_header(nullptr)
	, _bet_header(nullptr)
	, _file_indices(nullptr)
	, _bet_hashes(nullptr)
	, _het_hashes(nullptr)
	, _bet_file_table(nullptr)
	, _bet_file_flags(nullptr)
{
	init_crypt_table();
}

uint32_t MpqLoader::hash_string(const char *lpszString, uint32_t dwHashType)
{
	uint32_t seed1 = 0x7FED7FEDL;
	uint32_t seed2 = 0xEEEEEEEEL;
	while (*lpszString) {
		int ch = toupper(*lpszString++);

		seed1 = _crypt_table[(dwHashType * 0x100) + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}
	return seed1;
}

void MpqLoader::init_crypt_table()
{
	// The encryption and hashing functions use a number table in their procedures.
	// This table must be initialized before the functions are called the first time.

	uint32_t seed = 0x00100001;

	for (int index1 = 0; index1 < 0x100; index1++) {
		for (int index2 = index1, i = 0; i < 5; i++, index2 += 0x100) {
			uint32_t temp1, temp2;

			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;

			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			_crypt_table[index2] = (temp1 | temp2);
		}
	}
}

bool MpqLoader::load_file(const char *filename, uint8 **data, uint64 *len)
{
	int32 idx = find_file(filename);
	if (idx == -1)
		return false;

	uint32 filepos, file_size, compressed_size, flags, unknown;
	if (!load_file_data(idx, &filepos, &file_size, &compressed_size, &flags, &unknown))
		return false;

	if (flags & MPQ_FILE_COMPRESSED) {

		// read compressed data
		scoped_array<byte> compressed(new byte[compressed_size]);
		f.read_ofs(compressed.get(), filepos, compressed_size, NULL);

		// allocate memory for the uncompressed data
		uint8 *buf = new byte[file_size];

		if (flags & MPQ_FILE_IMPLODE) {

			// TODO: fix read_buf/write_buf
/*
			scoped_array<byte> exploded(new byte[filesize]);
			TDcmpStruct buf;
			ZeroMemory(&buf, sizeof(buf));
			explode(read_buf, write_buf, (char *)&buf, (void *)tmp.get());
*/
		}

		if (flags & MPQ_FILE_COMPRESS) {

			vector<uint32> ofs;
			const int num_blocks = file_size / (512 * (1 << _header.sector_size_shift));
			for (int i = 0; i < num_blocks+1; ++i)
				ofs.push_back(((uint32*)compressed.get())[i]);

			// Add the compressed size to be able to compute block size easily (cur_ofs[i+1] - cur_ofs[i])
			ofs.push_back(compressed_size);

			uint32 decomp_ofs = 0;  // offset into the decompressed data
			for (size_t i = 0, e = ofs.size()-1; i < e; ++i) {

				byte *cur = &compressed[ofs[i]];
				// first byte is the compression mask
				uint8 compression_mask = *cur++;

				if (compression_mask & MPQ_COMPRESSION_HUFFMANN) {
					printf("MPQ_COMPRESSION_HUFFMANN\n");
				}
				if (compression_mask & MPQ_COMPRESSION_ZLIB) {
					uLongf dst_size = file_size;
					uLongf src_size = ofs[i+1] - ofs[i] - 1;
					uncompress(&buf[decomp_ofs], &dst_size,  &compressed[ofs[i]+1], src_size);
					decomp_ofs += dst_size;
					printf("MPQ_COMPRESSION_ZLIB\n");
				}
				if (compression_mask & MPQ_COMPRESSION_PKWARE) {
					printf("MPQ_COMPRESSION_PKWARE\n");
				}
				if (compression_mask & MPQ_COMPRESSION_BZIP2) {
/*
					scoped_array<char> dst(new char[filesize]);
					uint32 s = filesize;
					BZ2_bzBuffToBuffDecompress(dst.get(), &s, (char *)(tmp.get() + 1), compressed_size-1, 0, 0);
*/
					printf("MPQ_COMPRESSION_BZIP2\n");
				}
				if (compression_mask & MPQ_COMPRESSION_SPARSE) {
					printf("MPQ_COMPRESSION_SPARSE\n");
				}
				if (compression_mask & MPQ_COMPRESSION_ADPCM_MONO) {
					printf("MPQ_COMPRESSION_ADPCM_MONO\n");
				}
				if (compression_mask & MPQ_COMPRESSION_ADPCM_STEREO) {
					printf("MPQ_COMPRESSION_ADPCM_STEREO\n");
				}

			}
		}

		*data = buf;
		*len = file_size;
	}

	return true;

}

bool MpqLoader::load_file_data(int32 idx, uint32 *file_pos, uint32 *file_size, uint32 *compressed_size, uint32 *flags, uint32 *unknown)
{
	*file_pos = packed_bits<uint32>(_bet_file_table, _bet_header->dwTableEntrySize * idx + _bet_header->dwBitIndex_FilePos, _bet_header->dwFilePosBits);
	*file_size = packed_bits<uint32>(_bet_file_table, _bet_header->dwTableEntrySize * idx + _bet_header->dwBitIndex_FileSize, _bet_header->dwFileSizeBits);
	*compressed_size = packed_bits<uint32>(_bet_file_table, _bet_header->dwTableEntrySize * idx + _bet_header->dwBitIndex_CompressedSize, _bet_header->dwCompressedSizeBits);
	uint32 flag_index = packed_bits<uint32>(_bet_file_table, _bet_header->dwTableEntrySize * idx + _bet_header->dwBitIndex_FlagIndex, _bet_header->dwFlagsBits);
	if (flag_index >= _bet_header->dwFlagCount)
		return false;
	*flags = _bet_file_flags[flag_index];
	*unknown = packed_bits<uint32>(_bet_file_table, _bet_header->dwTableEntrySize * idx + _bet_header->dwBitIndex_Unknown, _bet_header->dwUnknownBits);
	return true;
}

int32_t MpqLoader::find_file(const char *filename_org)
{
	char *filename = strdup(filename_org);
	strlwr(filename);

	uint32_t c = 2, b = 1;
	hashlittle2(filename, strlen(filename), &c, &b);
	uint64_t h = c + (((uint64_t)b) << 32);

	// mask the hash if needed (and set highest bit to 1)
	uint64_t and_mask = fill_bits<uint64_t>(_het_header->dwHashEntrySize);
	h &= and_mask;
	h |= (uint64_t)1 << (_het_header->dwHashEntrySize - 1);

	// het uses the highest 8 bits, bet uses rest
	uint8_t het_hash = (uint8_t)(h >> (_het_header->dwHashEntrySize - 8));
	uint64_t bet_hash = h & fill_bits<uint64_t>(_het_header->dwHashEntrySize - 8);

	int org_idx, idx;
	org_idx = idx = h % _het_header->dwHashTableSize;
	bool found = false;
	while (true) {
		byte h = _het_hashes[idx];
		if (h == het_hash) {
			// get the file index
			uint32_t file_idx = packed_bits<uint32_t>(_file_indices, idx * _het_header->dwTotalIndexSize, _het_header->dwIndexSize);
			uint64_t bb = packed_bits<uint64_t>(_bet_hashes, file_idx * _bet_header->dwTotalBetHashSize, _bet_header->dwBetHashSize);
			if (bb == bet_hash) {
				free(filename);
				return file_idx;
			}
		}

		idx = (idx + 1) % _het_header->dwHashTableSize;
		if (idx == org_idx)
			break;
	}

	free(filename);
	return -1;
}


void MpqLoader::decrypt_data(void *lpbyBuffer, uint32_t dwLength, uint32_t dwKey)
{
	uint32_t *lpdwBuffer = (uint32_t *)lpbyBuffer;
	uint32_t seed = 0xEEEEEEEEL;
	uint32_t ch;

	dwLength /= sizeof(uint32_t);

	while(dwLength-- > 0) {
		seed += _crypt_table[0x400 + (dwKey & 0xFF)];
		ch = *lpdwBuffer ^ (dwKey + seed);

		dwKey = ((~dwKey << 0x15) + 0x11111111L) | (dwKey >> 0x0B);
		seed = ch + seed + (seed << 5) + 3;

		*lpdwBuffer++ = ch;
	}
}

bool MpqLoader::load(const char *filename)
{
	// todo: build some kind of windowed wrapper on top of this..
	if (!f.open(filename))
		return false;

	if (!find_header(f, &_header))
		return false;

	if (_header.header_size != sizeof(MpqHeader))
		return false;

	// only support cataclysm
	if (_header.format_version != 3)
		return false;

	// read the block table
	int bt_size = _header.block_table_entries * sizeof(BlockTableEntry);

	_block_table.reset(new BlockTableEntry[_header.block_table_entries]);
	f.read_ofs(_block_table.get(), ((uint64_t)_header.block_table_offset_high << 32) + _header.block_table_offset, bt_size, NULL);
	uint32_t bt_key = hash_string("(block table)", HashTypeBlockTable);
	decrypt_data(_block_table.get(), bt_size/4, bt_key);

	// read the hash table
	int ht_size = _header.hash_table_entries * sizeof(HashTableEntry);
	_hash_table.reset(new HashTableEntry[_header.hash_table_entries]);
	f.read_ofs(_hash_table.get(), ((uint64_t)_header.hash_table_offset_high << 32) + _header.hash_table_offset, ht_size, NULL);
	uint32_t ht_key = hash_string("(hash table)", HashTypeBlockTable);
	decrypt_data(_hash_table.get(), ht_size/4, ht_key);

	// read the het table
	if (!_header.het_table_offset64)
		return false;

	_het_data.reset(new byte[(uint32_t)_header.het_table_size64]);
	f.read_ofs(_het_data.get(), _header.het_table_offset64, (uint32_t)_header.het_table_size64, NULL);
	if (!verify_md5(_het_data.get(), (int)_header.het_table_size64, _header.md5_het_table))
		return false;

	_het_header = (HetTable *)_het_data.get();
	decrypt_data(_het_data.get() + sizeof(ExtendedTableHeader), _het_header->dwDataSize, hash_string("(hash table)", HashTypeBlockTable));
	if (_het_header->dwDataSize != _het_header->dwTableSize)
		return false;

	// set up pointers to the variable length data after the header
	_het_hashes = _het_data.get() + sizeof(HetTable);
	_file_indices = _het_hashes + _het_header->dwHashTableSize;

	// read the bet table
	if (!_header.bet_table_offset64)
		return false;

	_bet_data.reset(new byte[(uint32_t)_header.bet_table_size64]);
	f.read_ofs(_bet_data.get(), _header.bet_table_offset64, (uint32_t)_header.bet_table_size64, NULL);
	if (!verify_md5(_bet_data.get(), (int)_header.bet_table_size64, _header.md5_bet_table))
		return false;

	_bet_header = (BetTable *)_bet_data.get();
	decrypt_data(_bet_data.get() + sizeof(ExtendedTableHeader), _bet_header->dwDataSize, hash_string("(block table)", HashTypeBlockTable));
	if (_bet_header->dwDataSize != _bet_header->dwTableSize)
		return 1;
	_bet_file_flags = (uint32 *)(_bet_data.get() + sizeof(BetTable));
	_bet_file_table = (uint8_t *)_bet_file_flags + _bet_header->dwFlagCount * sizeof(DWORD);
	_bet_hashes = _bet_file_table + (_bet_header->dwTableEntrySize * _bet_header->dwFileCount + 7) / 8;

	return true;
}

uint32 ofs = 0;
extern "C"
{
	unsigned int read_buf(char *buf, unsigned int *size, void *param)
	{
		memcpy(buf, (uint8 *)param + ofs, *size);
		ofs += *size;
		return *size;
	}

	void write_buf(char *buf, uint32 *size, void *param)
	{

	}

};

void intrusive_split(char *str, char sep, vector<const char *> *splits)
{
	char *last = str;
	char *p = str;
	while (*last && (p = strchr(last, sep))) {
		*p = '\0';
		splits->push_back(last);
		last = ++p;
	}

	if (*last)
		splits->push_back(last);
}

bool MpqLoader::extract(const char *filename)
{

	uint8 *buf;
	uint64 len;

	if (!load_file(filename, &buf, &len))
		return false;

	string2 ff(filename);
	vector<const char *> splits;
	intrusive_split(ff.str(), '\\', &splits);

	char cwd[MAX_PATH];
	_getcwd(cwd, sizeof(cwd));

	for (size_t i = 0; i < splits.size() - 1; ++i) {
		_mkdir(splits[i]);
		_chdir(splits[i]);
	}

	_chdir(cwd);

	FILE *f = fopen(filename, "wb");
	fwrite(buf, 1, (size_t)len, f);
	fclose(f);

	return true;
}

namespace adt {

struct ChunkHeader {
	union {
		uint32 tag;
		char ctag[4];
	};
	uint32 data_size;
};

struct MVER : public ChunkHeader {
	uint32 version;
};

struct MCIN : public ChunkHeader {
	struct Entry {
		void *mcnk;
		uint32 size;
		uint32 flags;
		uint32 async_id;
	} entries[16*16];
};

struct MTEX : public ChunkHeader {
	const char *filenames;
};

struct MMDX : public ChunkHeader {

};

struct MMID : public ChunkHeader {

};

struct MWMO : public ChunkHeader {
	const char *filenames;
};

struct MWID : public ChunkHeader {

};

struct MDDF : public ChunkHeader {

};

struct MODF : public ChunkHeader {

};

struct MFBO : public ChunkHeader {

};

struct MH2O : public ChunkHeader {

};

struct MTFX : public ChunkHeader {

};


struct MHDR : public ChunkHeader {
	uint32 flags;
	MCIN *mcin;
	MTEX *mtex;
	MMDX *mmdx;
	MMID *mmid;
	MWMO *mwmo;
	MWID *mwid;
	MDDF *mddf;
	MODF *modf;
	MFBO *mfbo;
	MH2O *mh2o;
	MTFX *mtfx;
	uint32 unused[4];
};

struct MCVT : public ChunkHeader {

};

struct MCNR : public ChunkHeader {

};

struct MCLY : public ChunkHeader {

};

struct MCRF : public ChunkHeader {

};

struct MCAL : public ChunkHeader {

};

struct MCSH : public ChunkHeader {

};

struct MCNK : public ChunkHeader {
	uint32 flags;
	uint32 index_x;
	uint32 index_y;
	uint32 layers;
	uint32 doodad_refs;
	MCVT *ptr_height;  // these are stored as offsets in the file, but we adjust them load time
	MCNR *ptr_normal;
	MCLY *ptr_layer;
	MCRF *ptr_refs;
	MCAL *ptr_alpha;
	uint32 size_alpha;
	MCSH *ptr_shadow;
	uint32 size_shadow;
};

#define MK_TAG(a, b, c, d) (a) << 24 | (b) << 16 | (c) << 8 | (d)

	void adt_parse(const uint8 *buf, int64 len)
	{
		int64 ofs = 0;
		while (ofs < len) {
			ChunkHeader header = *(ChunkHeader *)&buf[ofs];

			switch (header.tag) {
			case MK_TAG('M', 'V', 'E', 'R'):
				{
					MVER *mver = (MVER *)&buf[ofs];
					int a = 10;
				}
				break;

			case MK_TAG('M', 'H', 'D', 'R'):
				{
					MHDR *mhdr = (MHDR *)&buf[ofs];
					int a = 10;
				}
				break;

			case MK_TAG('M', 'C', 'I', 'N'):
				break;

			case MK_TAG('M', 'T', 'E', 'X'):
				{
					MTEX *mtex = (MTEX *)&buf[ofs];
					int a = 10;
				}
				break;

			case MK_TAG('M', 'M', 'D', 'X'):
				{
					MMDX *mmdx = (MMDX *)&buf[ofs];
					int a = 10;
				}
				break;

			case MK_TAG('M', 'M', 'I', 'D'):
				break;

			case MK_TAG('M', 'W', 'M', 'O'):
				{
					MWMO *mmdx = (MWMO *)&buf[ofs];
					int a = 10;
				}
				break;

			case MK_TAG('M', 'W', 'I', 'D'):
				break;

			case MK_TAG('M', 'D', 'D', 'F'):
				break;

			case MK_TAG('M', 'O', 'D', 'F'):
				{
					int a = 10;
				}
				break;

			case MK_TAG('M', 'H', '2', 'O'):
				{
					int a = 10;
				}
				break;

			case MK_TAG('M', 'C', 'N', 'K'):
				{
					MCNK *mcnk = (MCNK *)&buf[ofs];
					// fix up the pointers
#define FIXUP(type, p) mcnk->ptr_ ## p = mcnk->ptr_ ## p ? (type *)&buf[ofs + uintptr_t(mcnk->ptr_ ## p)] : 0;
					FIXUP(MCVT, height);
					FIXUP(MCNR, normal);
					FIXUP(MCLY, layer);
					FIXUP(MCRF, refs);
					FIXUP(MCAL, alpha);
					FIXUP(MCSH, shadow);

					int a = 10;
				}
				break;


			}

			ofs += sizeof(ChunkHeader) + header.data_size;

		}

	}

}

int _tmain(int argc, _TCHAR* argv[])
{
	MpqLoader loader;
	if (!loader.load("expansion3.mpq"))
		return 1;

	loader.extract("World\\maps\\AbyssalMaw\\AbyssalMaw_29_29.adt");

	uint8 *data;
	uint64 len;
	if (!loader.load_file("World\\maps\\AbyssalMaw\\AbyssalMaw_29_29.adt", &data, &len))
		return 1;

	adt::adt_parse(data, len);

	return 0;
}

