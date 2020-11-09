#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(WIN32) || defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* greet(char* user) {
  char *dest;
  char hello[] = "hello ";
  char end[] = "!";

  if (user != NULL) {
    strcat(dest, hello);
    strcat(dest, user);
    strcat(dest, end);

    return strdup(dest);
  } else {
    return "Name not provided as an argument";
  }

  
}