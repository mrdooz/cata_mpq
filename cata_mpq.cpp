#include "stdafx.h"
#include <celsus/MemoryMappedFile.hpp>
#include <cassert>
#include <celsus/celsus.hpp>
#include <boost/scoped_array.hpp>
#include <limits>
#include "md5.h"

using namespace std;
using namespace boost;

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

enum BlockTableFlags {
	kBtFlagsFile           = 0x80000000,
	kBtFlagsChecksum       = 0x04000000,
	kBtFlagsDeletionmarker = 0x20000000,
	kBtFlagsSingleUnit     = 0x10000000,
	kBtFlagsAdjustedKey    = 0x00020000,
	kBtFlagsEncrypted      = 0x00010000,
	kBtFlagsCompressed     = 0x00000200,
	kBtFlagsImploded       = 0x00000100,
};

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
	uint32_t dwBitIndex_FSize;                 // Bit index of the file size (within the entry record)
	uint32_t dwBitIndex_CSize;                 // Bit index of the compressed size (within the entry record)
	uint32_t dwBitIndex_FlagIndex;             // Bit index of the flag index (within the entry record)
	uint32_t dwBitIndex_Unknown;               // Bit index of the ??? (within the entry record)
	uint32_t dwFilePosBits;                    // Bit size of file position (in the entry record)
	uint32_t dwFileSizeBits;                   // Bit size of file size (in the entry record)
	uint32_t dwCmpSizeBits;                    // Bit size of compressed file size (in the entry record)
	uint32_t dwFlagsBits;                      // Bit size of flags index (in the entry record)
	uint32_t dwUnknownBits;                    // Bit size of ??? (in the entry record)
	uint32_t TotalNameHash2Size;               // Total size of the NameHashPart2 (in bits)
	uint32_t dwUnknown3C;
	uint32_t NameHash2Size;                    // Effective size of NameHashPart2 (in bits)
	uint32_t dwUnknown44;
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

uint32_t dwCryptTable[0x500];

// The encryption and hashing functions use a number table in their procedures.
// This table must be initialized before the functions are called the first time.
void init_crypt_table()
{
	uint32_t seed = 0x00100001;

	for (int index1 = 0; index1 < 0x100; index1++) {
		for (int index2 = index1, i = 0; i < 5; i++, index2 += 0x100) {
			uint32_t temp1, temp2;

			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;

			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			dwCryptTable[index2] = (temp1 | temp2);
		}
	}
}

void decrypt_data(void *lpbyBuffer, uint32_t dwLength, uint32_t dwKey)
{
	uint32_t *lpdwBuffer = (uint32_t *)lpbyBuffer;
	uint32_t seed = 0xEEEEEEEEL;
	uint32_t ch;

	dwLength /= sizeof(uint32_t);

	while(dwLength-- > 0) {
		seed += dwCryptTable[0x400 + (dwKey & 0xFF)];
		ch = *lpdwBuffer ^ (dwKey + seed);

		dwKey = ((~dwKey << 0x15) + 0x11111111L) | (dwKey >> 0x0B);
		seed = ch + seed + (seed << 5) + 3;

		*lpdwBuffer++ = ch;
	}
}

// Different types of hashes to make with hash_string
enum HashType {
	HashTypeTableOffset = 0,
	HashTypeMethodA = 1,
	HashTypeMethodB = 2,
	HashTypeBlockTable = 3,
};
/*
#define MPQ_HASH_TABLE_OFFSET	0
#define MPQ_HASH_NAME_A	1
#define MPQ_HASH_NAME_B	2
#define MPQ_HASH_FILE_KEY	3
*/
// Based on code from StormLib.
uint32_t hash_string(const char *lpszString, uint32_t dwHashType)
{
	uint32_t seed1 = 0x7FED7FEDL;
	uint32_t seed2 = 0xEEEEEEEEL;
	while (*lpszString) {
		int ch = toupper(*lpszString++);

		seed1 = dwCryptTable[(dwHashType * 0x100) + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}
	return seed1;
}

#define BLOCK_OFFSET_ADJUSTED_KEY 0x00020000L

uint32_t compute_file_key(const char *lpszFilePath, const BlockTableEntry &blockEntry, uint32_t nArchiveOffset)
{
	// Find the file name part of the path
	const char *lpszFileName = strrchr(lpszFilePath, '\\');
	if (lpszFileName)
		lpszFileName++;	// Skip the '\'
	else
	lpszFileName = lpszFilePath;

	// Hash the name to get the base key
	uint32_t nFileKey = hash_string(lpszFileName, HashTypeBlockTable);

	// Offset-adjust the key if necessary
	if (blockEntry.flags & kBtFlagsAdjustedKey)
		nFileKey = (nFileKey + blockEntry.ofs) ^ blockEntry.file_size;

	return nFileKey;
}

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

void read_block_table(MpqHeader *header, void *data)
{
	byte *ptr = (byte *)data + header->block_table_offset + ((int64_t)(header->block_table_offset_high) << 32);
	uint32_t key = hash_string("(block table)", HashTypeTableOffset);
	int32_t len = header->block_table_entries * sizeof(BlockTableEntry);
	BlockTableEntry *block_table = new BlockTableEntry[header->block_table_entries];
	memcpy(block_table, ptr, len);
	decrypt_data(block_table, len, key);
	delete [] block_table;
}

void read_hash_table(MpqHeader *header, void *data)
{

}

void read_het_table(MpqHeader *header, void *data)
{
	ExtendedTableHeader *p = (ExtendedTableHeader *)data;
	int a = 10;
}

void read_bet_table(MpqHeader *header, void *data)
{

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
bool bit_compare(const T *base, int ofs, T key, uint32_t len)
{
	// look for key of length len bits, starting at base + ofs (ofs is in bits)
	const T TSize = 8 * sizeof(T);

	T ofs_mod = ofs % TSize;
	// do we need to compare across boundaries?
	if (TSize - ofs_mod >= len) {
		// no
		T key_mask = fill_bits<T>(len);
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


int _tmain(int argc, _TCHAR* argv[])
{
	init_crypt_table();

	// todo: build some kind of windowed wrapper on top of this..
	FileReader f;
	if (!f.open("expansion3.mpq"))
		return 1;

	MpqHeader header;
	if (!find_header(f, &header))
		return 1;

	if (header.header_size != sizeof(MpqHeader))
		return 1;

	// only support cataclysm
	if (header.format_version != 3)
		return 1;

	// read the block table
	int bt_size = header.block_table_entries * sizeof(BlockTableEntry);

	scoped_array<BlockTableEntry> block_table(new BlockTableEntry[header.block_table_entries]);
	f.read_ofs(block_table.get(), ((uint64_t)header.block_table_offset_high << 32) + header.block_table_offset, bt_size, NULL);
	uint32_t bt_key = hash_string("(block table)", HashTypeBlockTable);
	decrypt_data(block_table.get(), bt_size/4, bt_key);

	// read the hash table
	int ht_size = header.hash_table_entries * sizeof(HashTableEntry);
	scoped_array<HashTableEntry> hash_table(new HashTableEntry[header.hash_table_entries]);
	f.read_ofs(hash_table.get(), ((uint64_t)header.hash_table_offset_high << 32) + header.hash_table_offset, ht_size, NULL);
	uint32_t ht_key = hash_string("(hash table)", HashTypeBlockTable);
	decrypt_data(hash_table.get(), ht_size/4, ht_key);

	// read the het table
	if (!header.het_table_offset64)
		return 1;

	scoped_array<byte> het_data(new byte[(uint32_t)header.het_table_size64]);
	f.read_ofs(het_data.get(), header.het_table_offset64, (uint32_t)header.het_table_size64, NULL);
	if (!verify_md5(het_data.get(), (int)header.het_table_size64, header.md5_het_table))
		return 1;

	const HetTable *het_header = (HetTable *)het_data.get();
	decrypt_data(het_data.get() + sizeof(ExtendedTableHeader), het_header->dwDataSize, hash_string("(hash table)", HashTypeBlockTable));
	if (het_header->dwDataSize != het_header->dwTableSize)
		return 1;

	uint32_t a, b;
	const char *listfile = "(listfile)";
	hashlittle2(listfile, strlen(listfile), &b, &a);
	uint64_t h = (((uint64_t)a) << 32) | b;

// mask the hash if needed (and set highest bit to 1)
	uint64_t and_mask = fill_bits<uint64_t>(het_header->dwHashEntrySize);
	h |= (uint64_t)1 << (het_header->dwHashEntrySize - 1);
		//std::limits (1u64 << (het_header->dwHashEntrySize - 1));

	// het uses the highest 8 bits
	uint8_t het_hash = (uint8_t)(h >> (het_header->dwHashEntrySize - 8));

	// bet uses rest
	uint64_t bet_hash = h & (and_mask >> 8);

	uint8_t *het_hashes = het_data.get() + sizeof(HetTable);

	int idx = h % het_header->dwHashTableSize;
	bool found = false;
	while (het_hashes[idx]) {
		if (het_hashes[idx] == het_hash) {
			found = true;
			break;
		}
		++idx;
	}

	if (!found) {
		// bad things..
	}



	uint32_t aa = 0x3 << 15;
	bool k = bit_compare<uint16_t>((uint16_t *)&aa, 14, 0x3, 2);


	//TMPQHetTable *het_table = (TMPQHetTable *)((byte *)het_data.get() + sizeof(HetTable));


	// read the bet table

	uint32_t lf_hashes[] = {
		hash_string("(listfile)", 0),
		hash_string("(listfile)", 1),
		hash_string("(listfile)", 2),
		hash_string("(listfile)", 3),
		hash_string("(listfile)", 4),
		hash_string("(listfile)", 5),
	};

	for (int i = 0; i < header.hash_table_entries; ++i) {
		HashTableEntry *cur = &hash_table[i];
		uint32_t a = hash_table[i].hash_a;
		uint32_t b = hash_table[i].hash_b;
		for (int j = 0; j < ELEMS_IN_ARRAY(lf_hashes); ++j) {
			if (lf_hashes[j] == a || lf_hashes[j] == b) {
				int bb = 10;
			}
		}
	}




	int cBufferSize = 16 * 1024;
	void *data = new byte[cBufferSize];

	if (header.het_table_offset64) {
		ExtendedTableHeader ext_header;
		f.read_ofs((void *)&ext_header, header.het_table_offset64, sizeof(ext_header), NULL);
		void *buf = new byte[ext_header.data_size];
		f.read_ofs(buf, header.het_table_offset64 + sizeof(ext_header), ext_header.data_size, NULL);
		int a = 10;
	}

	read_block_table(&header, data);

	delete [] data;


	return 0;
}

