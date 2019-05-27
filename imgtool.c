#include <fcntl.h>  // O_RDONLY, etc..
#include <unistd.h>
#include <stdlib.h> // exit(), etc..
#include <string.h> // strncmp, etc.
#include <stdio.h>  // printf(), etc..
#include <sys/stat.h> // mkdir(), stat()...
#include <errno.h>
#include <sys/mman.h> // mmap(), etc
#include <zlib.h>
#ifdef HAVE_LIBSPARSE
#include "sparse_file.h"
#endif
#ifdef HAVE_SHA
#include "sha.h"
#endif

void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen);



#define VERSION	"0.8 (FBPK)"
/**
  *
  * Rudimentary Android image and partition unpacking tool
  *
  * v0.1 - Support unpacking of BootLoader and Boot images, as well as imgdata
  * v0.2 - Supports offset= (for HTC and other boot.imgs where ANDROID! is wrapped)
  *        Supports cmdline= (to override kernel command line)
  *
  * v0.3 - Integrated mkbootimg functionality, added dt_size and id
  *
  * v0.4 - cmdline, addrs..
  *
  * v0.4.1 - Fix for Edvard Holst on Essential PH1 images..
  * 
  * v0.5 - Update with LZ4 binaries, fix for extract devicetree even if can't uncompress kernel
  *
  * v0.6 - Samsung images (with DT > 0) - Device Tree now found whereever it may hide
  *
  * v0.7 - system.transfer.list support
  *
  * v0.8 - FBPK (SD845 CrossHatch (Pixel 3 XL) bootloader images) AND Huawei Mate
  *        Also compiles cleanly
  *
  * @TODO: IMGDATA
  * @TODO: cache/userdata/system.img support - via simg
  *
  * This tool is part of the free downloads for the book "Android Internals: A Confectioner's Cookbook"
  *
  * Author: Jonathan Levin, http://NewAndroidBook.com
  *
  **/


#define GZ_MAGIC "\x1f\x8b\x08\x00\x00\x00\x00\x00"
#define LZ4_MAGIC  "\x04\x22\x4d\x18"
#define LZO_MAGIC "\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a"
//#define LZO_MAGIC "\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a"


#define SIMG_MAGIC	0xed26ff3a

struct simg_header
{

	uint32_t	magic;
	uint16_t	version_major;
	uint16_t	version_minor;
	uint16_t	header_size;
	uint16_t	chunk_size;
	uint32_t	block_size;
	uint32_t	num_blocks;
	uint32_t	num_chunks;
	uint32_t	checksum;


};

// From releasetools.pl:

#define BOOTLDR_MAGIC "BOOTLDR!"
#define BOOTLDR_MAGIC_SIZE 8

struct bootloader_images_header {
         char magic[BOOTLDR_MAGIC_SIZE];
         unsigned int num_images;
         unsigned int start_offset;
         unsigned int bootldr_size;
         struct {
                 char name[64];
                 unsigned int size;
         } img_info[];
};



// Verbatim copy from bootimg.h

typedef struct boot_img_hdr boot_img_hdr;

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512


// q.v. https://www.codeaurora.org/cgit/quic/la/kernel/lk/tree/app/aboot/bootimg.h
struct boot_img_hdr
{
    unsigned char magic[BOOT_MAGIC_SIZE];

    unsigned kernel_size;  /* size in bytes */
    unsigned kernel_addr;  /* physical load addr */

    unsigned ramdisk_size; /* size in bytes */
    unsigned ramdisk_addr; /* physical load addr */

    unsigned second_size;  /* size in bytes */
    unsigned second_addr;  /* physical load addr */

    unsigned tags_addr;    /* physical addr for kernel tags */
    unsigned page_size;    /* flash mmapped size we assume */
    unsigned dt_size;	   /* In newer versions of bootimg.h */
		// q.v bootimg.h?h=master&id=5e68eb8a09820d8447cb209558fbc237fcbfc41f

    unsigned unused[1];    /* future expansion: should be 0 */

    unsigned char name[BOOT_NAME_SIZE]; /* asciiz product name */
    
    unsigned char cmdline[BOOT_ARGS_SIZE];

    unsigned id[8]; /* timestamp / checksum / sha1 / etc */
};

/*
** +-----------------+ 
** | boot header     | 1 page 
** +-----------------+
** | kernel          | n pages  
** +-----------------+
** | ramdisk         | m pages  
** +-----------------+
** | second stage    | o pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/

#if 0
typedef struct ptentry ptentry;

struct ptentry {
    char name[16];      /* asciiz partition name    */
    unsigned start;     /* starting block number    */
    unsigned length;    /* length in blocks         */
    unsigned flags;     /* set to zero              */
};

/* MSM Partition Table ATAG
**
** length: 2 + 7 * n
** atag:   0x4d534d70
**         <ptentry> x n
*/
#endif


// From reverse engineering

#define IMGDATA_MAGIC "IMGDATA!"
struct imgdata_header {
         char magic[BOOTLDR_MAGIC_SIZE];
	 unsigned int unknown;
         unsigned int num_images;
         unsigned int unknown1;
         unsigned int unknown2;
         struct {
                 char name[16];
                 unsigned int width;
		 unsigned int height;
		 unsigned int unknown3;
		 unsigned int unknown4;
		 unsigned int flash_offset;
		 unsigned int flash_size;
         } img_info[];
};


// Let's get to work

#define EXTRACTED_DIR	"extracted"

#define true	1
#define	false	0

#ifdef HAVE_LIBSPARSE
int extractSimg (int in)
{
   mkdir("extracted", 0755);
   int out = open ("extracted/image.img", O_WRONLY | O_CREAT);
   if (out < 0 ) {perror ("extracted/image.img"); exit(1);}
  fchmod(out, 0644);

		struct sparse_file *s = sparse_file_import(in, true, false);
                if (!s) {
                        fprintf(stderr, "Failed to read sparse file\n");
                        exit(-1);
                }

                lseek(out, SEEK_SET, 0);

                int ret = sparse_file_write(s, out, false, false, false);
                if (ret < 0) {
                        fprintf(stderr, "Cannot write output file\n");
                        exit(-1);
                }
                sparse_file_destroy(s);
                close(in);

  printf("Extracted image is in extracted/image.img\n");
  return (0);

}
#else
int extractSimg(int in)
{
	printf("This version of imgtool was compiled without libsparse - can't extract simg files\n");
}
#endif

int extractDT (char *mmapped, int size)
{
    // Known Bug: There may be more than one device tree. This only finds the first one.
    // Yeah. I know.
#define DT_MAGIC 0xd00dfeed
    int j = 0;
    int dt_magic = ntohl(DT_MAGIC);
    for (j =  0  ;  j <  size; j++)
	{
		if ( memcmp (mmapped + j , &dt_magic, sizeof(int)) == 0)
		{
			fprintf(stderr, "Found DT Magic @%x\n", j);
			int dtFd = open ("extracted/devicetree.dtb", O_WRONLY | O_CREAT | O_TRUNC);
			write (dtFd, mmapped + j , size - j);
			fchmod (dtFd, 0600);
			close (dtFd);
			return 0;
			break;
		}
	}
   fprintf(stderr," Unable to locate device tree\n");
  return 1;
} // extractDT


int decompressKernel (unsigned char *kernel, int size)
{

    int i = 0;

    int gz =0, lzo = 0, lz4= 0;


    
    for (i = 0; i < size; i++)
        {

    		if (memcmp(kernel +i, LZ4_MAGIC, 4) == 0) {
			 fprintf(stderr, "Found LZ4 Magic at offset %d\n",i);
                        lz4++;
                        break;
			}
                if (memcmp(kernel +i, GZ_MAGIC, 8) == 0)
                {
                        fprintf(stderr, "Found GZ Magic at offset %d\n",i);
			gz++;
                        break;
                }

		if (memcmp(kernel +i, LZO_MAGIC, 4) == 0)
		{

                        fprintf(stderr, "Found LZO Magic at offset %d\n",i);
			lzo++;
                        break;
		
		}
        } // end for


   // Quick & Dirty -
   // This version doesn't have GZip support, so instead we write out the compressed portion of the file, 
   // and then invoke gunzip - because we have the magic, it will take care of that.

    int outputFd = -1;

    mkdir (EXTRACTED_DIR,0755);
    if (gz)  outputFd  = open ( "extracted/kernelimage.gz", O_WRONLY | O_CREAT | O_TRUNC);
    if (lzo)  outputFd = open ( "extracted/kernelimage.lzo", O_WRONLY | O_CREAT | O_TRUNC);
    if (lz4)  outputFd = open ( "extracted/kernelimage.lz4", O_WRONLY | O_CREAT | O_TRUNC);
    
    if (!lz4 && ! gz && !lzo) { fprintf(stderr,"Can't find GZ, LZO *or* LZ4 signature here... won't decompress\n"); //return 1;

	}
    if (outputFd == -1) {   fprintf(stderr,"Can't extract kernel : %s\n", strerror(errno));}
    fchmod(outputFd, 0600);
    write (outputFd, kernel+i, size -i);


    close (outputFd);

 
   // The *easiest* way to uncompress a kernel - no sense bother with zlib when gunzip is a given.
   if (gz) {
   if (access("/usr/bin/gunzip", X_OK) == 0) { system("/usr/bin/gunzip -v extracted/kernelimage.gz"); return 0;}
   if (access("/bin/gunzip", X_OK) == 0) { system("/bin/gunzip -v extracted/kernelimage.gz"); return 0;} 
	fprintf(stderr, "This version of imgtool relies on gunzip to do extraction, but gunzip wasn't found\n");	
	return 1;
        
	}

   if (lz4) {
	if (access("/usr/bin/lz4", X_OK) == 0) { 
		system("/usr/bin/lz4 -d extracted/kernelimage.lz4"); return 0;
		}
	else { fprintf(stderr,"This version of imgtool relies on lz4 to do extraction, but lz4 wasn't found\n");}
	}


  return 0;
}



void extractPortion (char *mmapped, 
		     int   offset,
		     int   size,
		     char *name)
{
	
		chdir(EXTRACTED_DIR); 
	// extract a portion of a memory mapped file, mmapped, size bytes from offset. No bounds checking,
	// No nothin'.

	fprintf(stdout,"extracting %s\n", name);
	int fd = open (name, O_WRONLY | O_TRUNC | O_CREAT);
	fchmod (fd, 0666);  // yeah, permissions...
	if (fd < 0) {
		perror ("name");
		return;

	}
	write (fd, mmapped + offset, size);
	close (fd);

	chdir ("..");


}


char *makeImg (char *imgName, char *kernelName, char *ramdiskName, uint32_t Addr, char *CmdLine)
{

	int k = open (kernelName, O_RDONLY);
	if (k < 0) { perror (kernelName); return (char *)1001; }

	struct stat stbuf;
	int rc = fstat(k, &stbuf);
	int kernelSize = stbuf.st_size;


	int rd = open (ramdiskName, O_RDONLY);
	if (rd < 0) { perror (ramdiskName); return (char *) 1002; }
	rc = fstat(rd, &stbuf);
	int ramdiskSize = stbuf.st_size;


	char *mmappedKernel = mmap(NULL,
                        kernelSize,
                        PROT_READ,
                        MAP_PRIVATE,
                        k,
                        0);

	char *mmappedRamdisk = mmap(NULL,
                        ramdiskSize,
                        PROT_READ,
                        MAP_PRIVATE,
                        rd,
                        0);


	int out = open (imgName, O_CREAT | O_TRUNC | O_WRONLY);


	int doHeader = 0;

	if (doHeader)
	{

	 	struct extra_header {
			uint32_t	magic;
			uint32_t	zeros;
			uint32_t	total_size;
			uint32_t	_0x100;
			uint32_t	total_size_minus_0x200;
			uint32_t	_0x100_here;
			uint32_t	total_size_minus_0x100;
			uint32_t	_0x100_here_too;
			uint32_t	padding[256];


		} extra ;

		memset (&extra, '\0', sizeof(extra));
		extra.magic = 0x12345678;
		extra.total_size = 8543800;
		extra.total_size_minus_0x200 = extra.total_size - 0x200;
		extra.total_size_minus_0x100 = extra.total_size - 0x100;

	write (out, &extra, 256);
		
	}
	struct boot_img_hdr bih;
	memset (&bih, '\0', sizeof(bih));

	strncpy ((char*)bih.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);
	bih.kernel_size = kernelSize;
	bih.ramdisk_size = ramdiskSize;
	bih.second_size = bih.second_addr = 0;
	bih.page_size	= 4096;

	if (!Addr) Addr = 0x10008000;
	bih.kernel_addr  = Addr;

	bih.ramdisk_addr = Addr + 0x04000000; // (ramdiskSize/ bih.page_size);
	bih.second_addr  = 0x80f00000;
	bih.tags_addr = 0x8e000000;




	// Get Sha-1
#ifdef HAVE_SHA
	SHA_CTX ctx;
	const uint8_t* sha;


        SHA_init(&ctx);
    	SHA_update(&ctx, mmappedKernel, bih.kernel_size);
        SHA_update(&ctx, &bih.kernel_size, sizeof(bih.kernel_size));
        SHA_update(&ctx, mmappedRamdisk, bih.ramdisk_size);
        SHA_update(&ctx, &bih.ramdisk_size, sizeof(bih.ramdisk_size));
        SHA_update(&ctx, "", bih.second_size);
        SHA_update(&ctx, &bih.second_size, sizeof(bih.second_size));
        sha = SHA_final(&ctx);
        memcpy(bih.id, sha,
           SHA_DIGEST_SIZE > sizeof(bih.id) ? sizeof(bih.id) : SHA_DIGEST_SIZE);

#endif


	//@TODO: set name
	strncpy ((char *) bih.name, (char *) "1490613711",BOOT_NAME_SIZE);

	memset (bih.cmdline, '\0', sizeof(bih.cmdline));
	if (CmdLine)
	{
		strncpy((char *) bih.cmdline, (char *) CmdLine,BOOT_ARGS_SIZE-1);
	}
	else
	strcpy ((char *) bih.cmdline, (char *) "androidboot.hardware=flounder androidboot.selinux=disabled");

	write (out, &bih, sizeof(bih));

	int padding =  bih.page_size - sizeof(bih);

	char *pad = calloc(padding,1);
	write (out, pad, padding);
	free(pad);

	write (out, mmappedKernel, kernelSize);

	// Write the Ramdisk - but not so fast - must calculate this on a flash page size
	// integer boundary
	
	int whereWeAre = (sizeof(bih) + padding +  kernelSize);

	padding =  bih.page_size - ( whereWeAre % bih.page_size);

	pad = calloc(padding,1);
	write (out, pad, padding);
	free(pad);

	write (out, mmappedRamdisk, ramdiskSize);

	// And let's not forget the end padding, either..
	whereWeAre += padding + ramdiskSize;

	padding = bih.page_size - (whereWeAre % bih.page_size);
	pad = calloc(padding,1);
	write (out, pad, padding);
	free(pad);

	fchmod (out, 0600);


	close(out);

	return 0;

}

int doSTL (char *SND, int SNDSize, char *STL){

	// Scan the STL: (which is null terminated)
	// 3 
	// 132009                - # of blocks (so we get block size
	// 0                     - # No clue
	// 0                     - # No clue, either. I'm sure there's some documentation somewhere
	// erase 2,0,196608
	// new 26, 0, 32767, ... - # List of blocks


	
	int ver;
	int numBlocks;
	int zero;
	int zero2;
	int eraseArgs, first, last;

	int rc = sscanf (STL,
			 "%d\n%d\n%d\n%d\nerase %d,%d,%d\n",
			 &ver,
			 &numBlocks,
			 &zero,
			 &zero2,
			 &eraseArgs, &first, &last);



	if (rc !=7 ){ fprintf(stderr,"Can't parse system.transfer.list\n"); return 1;}

	if (eraseArgs !=2 ) { fprintf(stderr,"erase has more than two arguments?\n"); return 2;}
	
	if (SNDSize  / numBlocks != 4096) { fprintf(stderr,"Block size is not 4k?\n"); return 3;}

	if (first != 0) { fprintf(stderr,"First block to erase (%d) is not zero - This could be a problem\n", first);}

	// Catch rounding errors.. can actully just use this
	if (SNDSize != numBlocks * 4096) { fprintf(stderr,"Block size is not 4K?\n"); return 4;}


	char *new =strstr(STL, "new");
	if (!new) { fprintf(stderr,"Unable to find list of new blocks...\n"); return 5;}

	int numNew;
	rc  = sscanf  (new + 4, "%d", &numNew);

	if (rc != 1) { fprintf(stderr,"Unable to figure out how many new blocks we have..\n"); return 6;}

	// Now malloc

	int *list = malloc ((numNew +1 ) * sizeof(int));

	char *sep = strchr (new, ',');

	int i = 0;
	for (i = 0; i < numNew; i++)
	{
	
		if (!sep) { fprintf(stderr,"Malformed block list..\n"); return 7;}

		int rc = sscanf (sep + 1, "%d", &(list[i]));
		if (rc != 1) { fprintf(stderr,"Malformed block element at %s\n", sep +1); return 8; }

		if (getenv("JDEBUG")) fprintf(stderr,"Got block element : %d\n", list[i]);
		sep = strchr (sep +1, ',');

	}

	list[numNew] = -1; // for compatibility with my original list implementation..
	fprintf(stderr,"STL - # of blocks %d, numNew %d\n", numBlocks, numNew);


	// You can find this 

        int out = open ("/tmp/extracted.img", O_WRONLY | O_CREAT);

	fchmod (out, 0644);




  int blockSize = 4096;
        char *emptyBlock = calloc (blockSize, sizeof(char ));

	i = 0;

        uint32_t fromBlock = list[i];
        uint32_t toBlock = list[i+1];
        uint32_t padding = 0;
        
        
        uint64_t offset = fromBlock * blockSize;
        uint64_t inOffset = fromBlock *blockSize;

        while (fromBlock != -1) {

	if (getenv("JDEBUG")) { printf ("Writing chunk: From %d  to %d\n", fromBlock, toBlock); }

        int rc = 0;
        while (offset < toBlock *blockSize) {

               rc = write (out, 
                       SND + inOffset, blockSize);
                if (rc < blockSize) { perror ("write");}
                offset += blockSize;
                inOffset += blockSize;

  }

        fromBlock = list[i+2];
        
        if (fromBlock == -1) break;
	if (getenv ("JDEBUG")) { printf("Padding from %d till %d\n ", toBlock, fromBlock);}
        padding += (fromBlock - toBlock);
        
        while (offset < fromBlock * blockSize) {
                
                write (out, emptyBlock, blockSize);
                offset += blockSize;
        
        }

        toBlock = list[i+3];
        i+=2;
        } 
        

	 // Need to pad last blocks here
	for (i = offset/4096; i<last;i++) {
		write (out, emptyBlock, blockSize);
	}


	fprintf(stderr,"Image written to /tmp/extracted.img\n");
                
        fsync(out);
        close(out); 



// end if

	return 0;
}

int main (int argc, char **argv)
{

	
	if (argc < 2)
	{
		fprintf (stderr, "Usage: %s _img_name_  [stl=....|extract]\n",argv[0]);
		fprintf (stderr, "Where: _img_name_ is the name of an Android boot or bootloader image (or boot partition)\n");
		fprintf (stderr,"       [extract]  is an optional parameter to extract the image components\n");
		fprintf (stderr,"       [offset=...]  offset to find ANDROID! magic (e.g. 256 in HTC boot)\n");
		fprintf(stderr, "       [stl=] specifying a list file to reconstruct system.img from\n");
		fprintf (stderr,"\nor:     %s make _img_name_ _kernel_ _ramdisk_ [....]\n", argv[0]);
		fprintf (stderr,"        Make _img_name by combining kernel and ramdisk and creating header\n");
		fprintf (stderr,"       [cmdline='args to kernel'] is an optional parameter specifying the kernel command line\n");
		fprintf(stderr, "       [addr=0x.....] is an optional base address to load the kernel into\n");
    
	
		fprintf(stderr,"\n\nThis is ImgTool " VERSION " compiled on " __DATE__ "\n");
		exit(0);
	}

	if (strcmp(argv[1],"make") == 0)
	{
		char *addr =NULL;
		char *cmdline = NULL;
		if (argc <5)
		{
			fprintf (stderr,"Make: Requires at least three arguments - image name, kernel and ramdisk\n");
			exit(1);
		}
		else
		{
			int i = 0;
			for (i = 4; i < argc; i++)
			{
	  		if (strstr(argv[i], "cmdline=")) cmdline = (strstr(argv[i],"=") + 1);
	  if (strstr(argv[i], "addr=")) addr = (strstr(argv[i],"=") + 1);
			}
			// Assume argv[2-4] are image Name, kernel, ramdisk
			
		}
		uint32_t addrNum = 0;

		if (addr) { sscanf(addr, "%x", &addrNum);
		if (!addrNum) { fprintf(stderr,"Warning: Address '%s' is not valid hex\n", addr); }
		}
		makeImg (argv[2], argv[3], argv[4], addrNum ,cmdline);
		exit(0);

	}

	char *fileName = argv[1];
	int fd;
	int rc;
	int i;

	int offset = 0;
	int extract = 0;
	
	char *cmdline = NULL;

	char *stl =NULL;

	for (i = 1; i <= argc - 1; i++)
	{

	  if (strncmp(argv[i], "stl",3) == 0){
		if (argv[i][3] == '\0') { stl ="system.transfer.list";}
		else
		{

			stl = &argv[i][4];
		}

		if (access(stl, R_OK) != 0) {
			/* not cool */
			fprintf(stderr,"Unable to find transfer list file (%s)\n", stl);
			return 1;
		}

	  }
	  if (strncasecmp(argv[i], "extract", 7) == 0) {

		extract++;
		mkdir (EXTRACTED_DIR,0755);

		}
	  if (strstr(argv[i], "offset=")) {
			   sscanf (argv[i] + strlen("offset=") ,"%d", &offset);
			}
	}

	char *mmapped = NULL;
	
	struct stat stbuf = {0};

	rc = stat(fileName, &stbuf);

	if  (!(stbuf.st_mode & S_IFREG)) { fprintf (stderr,"%s is not a file\n", fileName); exit(6); }

	if (rc < 0) { perror(fileName); exit (5); }

 	fd = open (fileName, (cmdline? O_RDWR : O_RDONLY));
	if (fd < 0) { perror (fileName); exit(3);}

	uint64_t fileSize = stbuf.st_size;
	
	mmapped =  mmap(NULL,
			stbuf.st_size,
			(cmdline? PROT_WRITE : PROT_READ),
			MAP_PRIVATE,
			fd,
			0);



	if (!mmapped) { fprintf (stderr, "IAH, we have a problem...\n"); perror ("mmap"); exit(4); }


	if (offset) mmapped += offset;


	
	if (stl) {

		int x = open (stl, O_RDONLY);
		if (x <0){ perror (stl); return 1;}
		
		char *stlMapped = calloc(16384,1);
		
		
		int rc = read(x, stlMapped, 16384);

		
		if (rc <0){ perror (stl); return 1;}
		

		close (x);
		// We have a system.transfer.list
		return (doSTL (mmapped, stbuf.st_size, stlMapped));

		return 0;
	} // stl

	if (strncmp(mmapped,BOOT_MAGIC, strlen(BOOT_MAGIC)) == 0)
	{
		// This is a boot image
		printf("Boot image detected\n");



		struct boot_img_hdr *bih = (struct boot_img_hdr *) mmapped;

		
		// Just like the header says:

		int n = (bih->kernel_size + bih->page_size - 1) / bih->page_size;
		int m = (bih->ramdisk_size + bih->page_size - 1) / bih->page_size;
		int o = (bih->second_size + bih->page_size - 1) / bih->page_size;


		printf ("Part      \tSize      \tPages\t  Addr\n");
		printf ("Kernel:   \t%-8d\t%-5d\t0x%x\n", bih->kernel_size, n,bih->kernel_addr);
		printf ("Ramdisk:  \t%-8d\t%-5d\t0x%x\n", bih->ramdisk_size, m, bih->ramdisk_addr);
		printf ("Secondary:\t%-8d\t%-5d\t0x%x\n", bih->second_size, o, bih->second_addr);
		printf ("Tags:       %x\n", bih->tags_addr);
		printf ("Flash Page Size: %d bytes\n", bih->page_size);
		printf ("DT Size: %d bytes\n", bih->dt_size);
		printf ("ID: ");
		int id =0;
		for (id = 0 ; id <8 ; id++)
		{
			printf("%x", bih->id[id]);
		}
		printf("\n");


		printf ("Name:    %s\n", bih->name);
		printf ("CmdLine: %s\n", bih->cmdline);


		if (cmdline)
		{
			printf ("Overriding cmdline with %s\n", cmdline);

			strncpy ((char *)bih->cmdline, (char *) cmdline, BOOT_ARGS_SIZE);
			close(fd);
			fd = open (fileName, O_RDWR);
			mmapped -= offset;

			write (fd, mmapped, stbuf.st_size);
			close(fd);

			exit(0);
		}

		if (extract)
		{


			decompressKernel ((unsigned char *) (mmapped +  1 * bih->page_size), bih->kernel_size);
			extractPortion (mmapped, 1 * bih->page_size, bih->kernel_size, "kernel");
			extractPortion (mmapped, (n+1) * bih->page_size, bih->ramdisk_size, "ramdisk");
			if (bih->dt_size) {
				// look for DT after ramdisk
				int dt = (n+1) * bih->page_size + ((((bih->ramdisk_size) /bih->page_size) + 2) * bih->page_size);
				printf("Searching for DT at 0x%x\n", dt);
				extractDT (mmapped + dt, bih->dt_size);
				
			}
			else {

				// look for DT in kernel
				extractDT (mmapped +1 *bih->page_size, bih->kernel_size); 


			}
			if (bih->second_size)
			{
			  // secondary is often not included in image (secondsize == 0)

			extractPortion (mmapped, (n+1) * bih->page_size, bih->second_size, "second");

			}

		} // extract

		exit(0);
	}

	if ((*((uint32_t *) mmapped)) == SIMG_MAGIC)
	{
		// This is a sparse image

		struct simg_header *si = (struct simg_header *) mmapped;

		printf("Sparse image v%d.%d detected, %d blocks of %d bytes\n", si->version_major, si->version_minor, si->num_blocks, si->block_size);

		uint64_t nbbs = (uint64_t) si->num_blocks * (uint64_t)si->block_size;
		if ((!si->num_blocks) || (!si->block_size))
		{
			printf("?!\n");
		}
		else
		{
	//	printf("%d\n", (si->num_blocks * si->block_size));
		printf("%d blocks of %d bytes compressed into %d chunks (%lld%% compressed)\n",
			si->num_blocks, si->block_size, si->num_chunks,
			100 - (100 * stbuf.st_size /  nbbs));

			}
		

		if (extract) extractSimg(fd);
		exit(0);


	}

	if (strncmp(mmapped,BOOTLDR_MAGIC, strlen(BOOTLDR_MAGIC)) == 0)
	{
		// This is a bootldr image
		printf("Boot loader detected\n");
		struct bootloader_images_header *bih = (struct bootloader_images_header *) mmapped;
		printf("%d images detected, starting at offset 0x%x. Size: %d bytes\n",
			bih->num_images,
			bih->start_offset,
			bih->bootldr_size);

		int total = 0;

		for (i = 0;
		     i <  bih->num_images;
		     i++)
		{
			printf ("Image: %d\tSize: %7d bytes\t%s\n",
				i,
				bih->img_info[i].size,
				bih->img_info[i].name);
			if (extract)
			{
				
				extractPortion (mmapped, bih->start_offset + total, bih->img_info[i].size,  bih->img_info[i].name);


			}

			total += bih->img_info[i].size;

		}


		if (total != bih->bootldr_size) fprintf (stderr,"Warning: Total mismatches reported bootloader size\n");

	

		
		exit(0);

	}
	
	
	if (strncmp(mmapped,IMGDATA_MAGIC, strlen(IMGDATA_MAGIC)) == 0)
	{
		printf("Image Data detected\n");
		struct imgdata_header *idh = (struct imgdata_header *) mmapped;
		printf("%d images detected, %d, %d %d\n",
			idh->num_images,
			idh->unknown,
			idh->unknown1,
			idh->unknown2);

		for (i = 0;
		     i <  idh->num_images;
		     i++)
		{
			printf ("Image: %d\tName: %16s\tDimensions: %5dx%-5d Unknowns: %5d %5d Offset: %7x Size: %7x\n",
				i,
				idh->img_info[i].name,
				idh->img_info[i].height,
				idh->img_info[i].width,
				idh->img_info[i].unknown3,
				idh->img_info[i].unknown4,
				idh->img_info[i].flash_offset,
				idh->img_info[i].flash_size);

			extractPortion (mmapped, idh->img_info[i].flash_offset, idh->img_info[i].flash_size,  idh->img_info[i].name);

		}
		exit(0);

	}
		
	// If we're still here, maybe this is one of those Lenovo images
	// So far from what I've seen it's always offset 0x4040, but I'm 
	// making this code generic (that is, brute force, not look for SFSF, etc)
	
	{
		// Try to autodetect SIMG_MAGIC
		
		uint32_t simg_magic = SIMG_MAGIC;

		// Gotta be some minimum size for an fs image...

		if (stbuf.st_size > 10000000) {

		char *simg_after_all = memmem (mmapped,
						   0x5000, // to cover 0x4040
						   &simg_magic,
						   sizeof(uint32_t));

		if (simg_after_all){
    		struct simg_header *si = (struct simg_header *) simg_after_all;

                printf("Sparse image v%d.%d detected (in container at offset 0x%lx)\n", si->version_major, si->version_minor, simg_after_all - mmapped );
                printf("%d blocks of %d bytes compressed into %d chunks (%lld%% compressed)\n",
                        si->num_blocks, si->block_size, si->num_chunks,
                        100 - (100 * stbuf.st_size / (si->num_blocks * si->block_size)) );

                lseek(fd, simg_after_all - mmapped,SEEK_SET );
		
                if (extract) extractSimg(fd);
                exit(0);

			}
		}

	}
						
#ifndef NO_08
	// Still here? Try new FBPK
	#define FBPK_MAGIC 0x4b504246
	#define FBPT_MAGIC 0x54504246

#if 0
00000000  46 42 50 4b 01 00 00 00  62 31 63 31 2d 30 2e 31  |FBPK....b1c1-0.1|
00000010  2d 35 30 33 34 36 36 39  00 00 00 00 00 00 00 00  |-5034669........|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000040  00 00 00 00 00 00 00 00  00 00 00 00 13 00 00 00  |................|
00000050  28 a7 84 00 00 00 00 00  70 61 72 74 69 74 69 6f  |(.......partitio|
00000060  6e 20 74 61 62 6c 65 00  00 00 00 00 00 00 00 00  |n table.........|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 68 0a 00 00  |............h...|
00000080  00 00 00 00 00 0b 00 00  77 9c 71 b5 46 42 50 54  |........w.q.FBPT|
00000090  01 00 00 00 00 00 00 00  00 00 00 00 15 00 00 00  |................|
000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#endif 

	struct fbpk {
		uint32_t	magic;
		uint32_t	versionMaybe;
		char		name[0x4c - 8];
		uint32_t	numParts;
		uint32_t	totalSize;
		} *fbpk = (struct fbpk *) mmapped;

	if (extract)  {
			mkdir (EXTRACTED_DIR, 0755); // yeah, I know. Insecure. Bleh
		   }

	if (fbpk->magic == FBPK_MAGIC) {

		fprintf(stderr,"QCom SD845 (\"FBPK\") image detected\n");
	
		struct partEntry {
#pragma pack(1)
			uint32_t	typeMaybe;
			char		label[32];
			uint32_t	zeroMaybe;
			uint32_t	payload_size_probably;
			uint32_t	anotherZero;
			uint32_t	next;
			uint32_t	checksum_probably;
#if 0
00000050  28 a7 84 00 00 00 00 00  70 61 72 74 69 74 69 6f  |(.......partitio|
00000060  6e 20 74 61 62 6c 65 00  00 00 00 00 00 00 00 00  |n table.........|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 68 0a 00 00  |............h...|
00000080  00 00 00 00 00 0b 00 00  77 9c 71 b5 46 42 50 54  |........w.q.FBPT|

00000b00  00 00 00 00 70 61 72 74  69 74 69 6f 6e 20 74 61  |....partition ta|
00000b10  62 6c 65 00 00 00 00 00  00 00 00 00 00 00 00 00  |ble.............|
00000b20  00 00 00 00 00 00 00 00  b0 01 00 00 00 00 00 00  |................|
00000b30  f0 0c 00 00 27 62 e8 b3  46 42 50 54 01 00 00 00  |....'b..FBPT....|
00000b40  01 00 00 00 00 00 00 00  03 00 00 00 00 00 00 00  |................|
00000b50  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
#endif

			} *partTable = (struct partEntry  *) (fbpk + 1);
#pragma pack()
	

		fprintf(stderr,"Partition Table with %d entries:\n", fbpk->numParts);

		if (fbpk->totalSize != fileSize) {

			fprintf(stderr,"Warning - File is truncated! Reported size (%d) does not match actual (%lld)\n",
				fbpk->totalSize , fileSize);
		}
 
		int p = 0;


		int off = 0;
		for (p = 0; p < fbpk->numParts; p++) {
			if (partTable->typeMaybe) {
			 printf("0x%x: %s ", off, partTable->label);
				// ..
			if (extract) {
				extractPortion (mmapped, off + sizeof(struct partEntry), partTable->next - off - sizeof(struct partEntry),
						partTable->label);
				}
			else printf("\n");
			}
			off = partTable->next;
			if (off > fileSize) {
				if (p < fbpk->numParts -1) {
					fprintf(stderr,"Warning: Next chunk reported @0x%x, but file size is only 0x%llx\n",
					off, fileSize);
				}
				break;
			}
			partTable = (struct partEntry *) (mmapped + partTable->next);
			

		}

		return 0;
			
	
	} // FBPK_MAGIC


	// Could be a Huawei image - UPDATE.APP - Magic here is 55 aa 5a a5

	#define HUAWEI_MAGIC	0xa55aaa55

	uint32_t hm = HUAWEI_MAGIC;
	uint32_t *mp = (uint32_t *)memmem (mmapped, 256, &hm, sizeof(hm));

	if (mp) { fprintf(stderr,"Huawei update image detected\n"); 

	while (*mp == HUAWEI_MAGIC) {
	

#pragma pack(1)
		struct huawei {
			uint32_t	magic;
			uint32_t	headerSize;
			uint32_t	versionMaybe;
			uint64_t	hw7x27ffff;
			uint32_t	unknown_fe;
			uint32_t	size;
			char		date[16];
			char		time[16];
			char 		name[32];
			uint32_t	unknown_0x100de8c;
			uint32_t	unknown_0x46690000;


		} * h = (struct huawei *) mp;
#pragma pack()
		
	  printf("0x%llx: Name: %s (%u bytes) Date: %s Time: %s\n", 
		(uint64_t) ((char *) mp - (char *)mmapped),
		h->name, 
		h->size,
		h->date, h->time);

          if (extract) {

			chdir (EXTRACTED_DIR);
		   int out = open (h->name, O_WRONLY | O_CREAT);
		   if (out < 0 ) {perror (h->name); exit(1);}
		   fchmod(out, 0644);
		   // Could end up with large images, so write in chunks of 32768
		   uint32_t toWrite = h->size;
		   uint32_t pos = h->headerSize;
		  
		   while (toWrite > 0) {
		   	rc = write (out, (char *)mp + pos, 32768UL < toWrite? 32768 : toWrite);
			pos += rc;
			if (toWrite < rc) {fprintf(stderr,"Underflow!\n"); break;}
			toWrite -= rc;
		   }
		   
		   close(out);
		}


	
	  mp = (uint32_t*) ((char *) mp + h->headerSize + h->size);

	uint64_t off = ((char *) mp - (char *)mmapped);
	if (off > fileSize) { fprintf(stderr,"Premature end of file! (0x%llx > 0x%llx)\n",
				off , fileSize) ; exit(0);}
	if (getenv("JDEBUG")) printf("MP NOW @0x%lx\n", (char *) mp - (char *)mmapped);
	
	  int align  = ((uint64_t) mp) % 4;
	  if (align) mp = (uint32_t *)((char *) mp + 4 -align);

#if 0
00000050  00 00 00 00 00 00 00 00  00 00 00 00 55 aa 5a a5  |............U.Z.|
00000060  64 00 00 00 01 00 00 00  48 57 37 78 32 37 ff ff  |d.......HW7x27..|
00000070  00 00 00 fe 00 01 00 00  32 30 31 37 2e 31 32 2e  |........2017.12.|
00000080  32 31 00 00 00 00 00 00  30 39 2e 31 31 2e 34 36  |21......09.11.46|
00000090  00 00 00 00 00 00 00 00  53 48 41 32 35 36 52 53  |........SHA256RS|
000000a0  41 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |A...............|
000000b0  00 00 00 00 00 00 00 00  8c de 00 10 00 00 69 46  |..............iF|
000000c0  17 b2 04 64 ea b3 58 2b  cf 2d 12 79 2f 9a ea d7  |...d..X+.-.y/...|

#endif

	
	
	} 	// while

	return(0);
	} // if mp



#endif
	fprintf (stderr,"%s is not a recognized image. Sorry\n", fileName);

}

