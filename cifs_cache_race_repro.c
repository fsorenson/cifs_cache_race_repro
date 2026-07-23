/*
	Frank Sorenson <frank.sorenson@gmail.com>, 2026

	cifs_cache_race_repro - reproduces a race condition that causes
	  directory cache corruption on a cifs filesystem.


	Windows Server's directory enumeration metadata lags behind the actual
	  file size after a write+close or rename.  A concurrent readdir() in
	  the window between close() returning to userspace and stat() being
	  called overwrites the correct cached i_size with the stale server
	  value, causing stat() to return the wrong size.

	the sequence of operations:
		fd = open(“work/a_#.temp”, O_CREAT|O_TRUNC)
		write(fd, buf, 1400)
		close(fd)
		stat("work/a_#.temp", &st) // <<<< bug if size != 1400

		fd = open("work/a_#.temp", O_CREAT|O_TRUNC)
		write(fd, buf, 1290)
		close(fd)
		stat("work/a_#.temp", &st) // <<<< bug if size != 1290

		rename("work/a_#.temp", "work/a_#")
		stat("work/a_#", &st) // <<<< bug if size != 1290

		truncate("work/a_#", 1100)
		stat("work/a_#", &st) // <<<< bug if size != 1100

		dfd = open(“work”, O_DIRECTORY)
		while (getdents(dfd) > 0) {}
		close(dfd)

	Usage: cifs_cache_race_repro <test_path> [<num_threads> [<num_iter>]]
	  <test_path> specifies the directory in which to run the test
	  <num_threads> allows for adjusting the number of simultaneous
	    threads; defaults to 5
	  <num_iter> allows for adjusting the number of iterations to
	    execute the test; defaults to INT_MAX

	Reproduction requires as few as 2 threads, but requires fewer
	  iterations with 5-10 threads
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>

#define DEFAULT_NUM_THREADS 5
#define DEFAULT_NUM_ITER INT_MAX
#define DIRENT_BUF_SIZE 65536
#define BUF_SIZE 4096
#define WRITE_SIZE1 1400
#define WRITE_SIZE2 1290
#define TRUNC_SIZE 1100

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define free_buf(x) do { \
	if (x) \
		free(x); \
	x = NULL; \
} while (0)
#define close_fd(x) do { \
	if (x >= 0) \
		close(x); \
	x = -1; \
} while (0)

#ifndef gettid
pid_t gettid(void) {
	return syscall(SYS_gettid);
}
#endif

int read_dir(const char *path) {
	char *dirent_buf = NULL;
	int dfd = -1, ret = EXIT_SUCCESS, nread;

	dirent_buf = malloc(DIRENT_BUF_SIZE);
	if ((dfd = open(path, O_DIRECTORY)) < 0) {
		output("error opening directory '%s': %m\n", path);
		goto out;
	}
	while (42) {
		if ((nread = syscall(SYS_getdents64, dfd, dirent_buf, DIRENT_BUF_SIZE)) < 0) {
			output("getdents call failed: %m\n");
			goto out;
		}
		if (nread == 0)
			break;
	}
	ret = EXIT_SUCCESS;
out:
	close_fd(dfd);
	free_buf(dirent_buf);

	return ret;
}

int write_bytes(const char *path, int fd, const char *buf, int count) {
	int written, write_offset = 0;

retry_write:
	if ((written = write(fd, buf + write_offset, count - write_offset)) != count - write_offset) {
		if (written < 0) {
			output("write of %d bytes to %s failed with %m\n", count, path);
			goto out;
		}
		output("write of %d bytes to %s succeeded, but only wrote %d ; retrying write of %d bytes\n",
			count - write_offset, path, written, count - write_offset - written);
		write_offset += written;
		goto retry_write;
	}
	written += write_offset;

out:
	return written;
}

#define try_stat(filename, st) do { \
	if (stat(filename, st) < 0) { \
		output("error calling stat on %s: %m\n", filename); \
		goto out; \
	} \
} while (0)

int process_one() {
	int fd = -1;
	char *filename1 = NULL, *filename2 = NULL, buf[BUF_SIZE];
	struct stat st;
	int ret = EXIT_FAILURE;
	pid_t tid = gettid();

	memset(buf, 'X', sizeof(buf));

	asprintf(&filename1, "work/file_%d.xml__temp", tid); // work/file_#.xml__temp
	asprintf(&filename2, "work/file_%d.xml", tid); // work/file_#.xml

	// cleanup/setup
	unlink(filename1);
	unlink(filename2);

	if ((fd = open(filename1, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // work/file_#.xml__temp
		output("error opening %s: %m\n", filename1);
		goto out;
	}
	if (write_bytes(filename1, fd, buf, WRITE_SIZE1) < 0)
		goto out;
	close_fd(fd); // work/file_#.xml__temp

	try_stat(filename1, &st); // work/file_#.xml__temp
	if (st.st_size != WRITE_SIZE1) {
		output("BUG: wrote %d bytes to file %s, but stat returned %ld\n", WRITE_SIZE1, filename1, st.st_size);
		goto out;
	}

	if ((fd = open(filename1, O_CREAT|O_TRUNC|O_RDWR, 0644)) < 0) { // work/file_#.xml__temp
		output("error opening %s: %m\n", filename1);
		goto out;
	}
	if (write_bytes(filename1, fd, buf, WRITE_SIZE2) < 0)
		goto out;
	close_fd(fd); // work/file_#.xml__temp

	try_stat(filename1, &st); // work/file_#.xml__temp
	if (st.st_size != WRITE_SIZE2) {
		output("BUG: wrote %d bytes to file %s, but stat returned %ld\n", WRITE_SIZE2, filename1, st.st_size);
		goto out;
	}

	if (rename(filename1, filename2) < 0) { // work/file_#.xml__temp, work/file_#.xml
		output("error renaming %s -> %s: %m\n", filename1, filename2);
		goto out;
	}
	try_stat(filename2, &st); // work/file_#.xml
	if (st.st_size != WRITE_SIZE2) {
		output("BUG: size of file after rename to '%s' should be %d, but is %ld\n",
			filename2, WRITE_SIZE2, st.st_size);
		goto out;
	}

	if (truncate(filename2, TRUNC_SIZE) < 0) { // work/file_#.xml
		output("error truncating %s to %d: %m\n", filename2, TRUNC_SIZE);
		goto out;
	}
	try_stat(filename2, &st); // work/file_#.xml
	if (st.st_size != TRUNC_SIZE) {
		output("BUG: truncated %s to %d bytes, but stat returned %ld\n", filename2, TRUNC_SIZE, st.st_size);
		goto out;
	}

	read_dir("work");

	unlink(filename2);
	ret = EXIT_SUCCESS;
out:
	close_fd(fd);
	free_buf(filename1); // work/file_#.xml__temp
	free_buf(filename2); // work/file_#.xml

	return ret;
}

typedef struct {
	int result;
} thread_data_t;

void* thread_wrapper(void *arg) {
	thread_data_t *data = (thread_data_t *)arg;
	data->result = process_one();
	return NULL;
}

int main(int argc, char *argv[]) {
	int num_threads = DEFAULT_NUM_THREADS, max_iter = DEFAULT_NUM_ITER;
	int failed_count = 0, iter = 0, i;
	thread_data_t *thread_data;
	char *test_path = argv[1];
	pthread_t *threads;

	if (argc < 2 || argc > 4) {
		output("Usage: %s <test_path> [<num_threads> [<iteration_count>]]\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (argc >= 3)
		num_threads = strtol(argv[2], NULL, 10);
	if (argc == 4)
		max_iter = strtol(argv[3], NULL, 10);

	if (chdir(test_path) < 0) {
		output("error changing to test path %s: %m\n", test_path);
		return EXIT_FAILURE;
	}
	if (mkdir("work", 0755) < 0 && errno != EEXIST) {
		output("error creating 'work' subdir: %m\n");
		return EXIT_FAILURE;
	}

	threads = malloc(num_threads * sizeof(pthread_t));
	thread_data = malloc(num_threads * sizeof(thread_data_t));

	while (iter++ < max_iter) {
		output("iteration %d - ", iter);

		for (i = 0; i < num_threads ; i++) {
			thread_data[i].result = EXIT_FAILURE;

			if (pthread_create(&threads[i], NULL, thread_wrapper, &thread_data[i]) != 0) {
				output("Error creating thread %d\n", i);
				return EXIT_FAILURE;
			}
		}

		// Reap all threads
		for (i = 0; i < num_threads ; i++) {
			pthread_join(threads[i], NULL);
			if (thread_data[i].result != EXIT_SUCCESS)
				failed_count++;
		}

		// Report results
		if (failed_count > 0) {
			output("FAILED: %d out of %d threads failed\n", failed_count, num_threads);
			return EXIT_FAILURE;
		} else
			output("SUCCESS: All %d threads completed successfully\n", num_threads);
	}
	return EXIT_SUCCESS;
}
